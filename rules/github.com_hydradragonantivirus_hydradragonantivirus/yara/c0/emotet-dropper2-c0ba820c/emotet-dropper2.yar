rule emotet_dropper2 {
  meta:
    description = "03-01-19 - file emotet-dropper2.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-03-01"
    hash1       = "0336745712f8e6c27dc7691c6d2bd938e8d4962c172f901124f18a9d8bd10ca8"

  strings:
    $s1 = "6576616c28677a696e666c617465286261736536345f6465636f64652822" ascii  
    $s2 = "echo $commandPart1 . \"[base64-encoded-value-here]\" . $commandPart2 . \"\\n\";" fullword ascii
    $s3 = "file_put_contents(\"/home/libra/Desktop/emotet/stage4.php\", (gzinflate(base64_decode(''))));" fullword ascii
    $s4 = "$commandPart1 = decode('6576616c28677a696e666c617465286261736536345f6465636f64652822');" fullword ascii
    $s5 = "echo \"Command equals:\\n\";" fullword ascii
    $s6 = "222929293b" ascii  
    $s7 = "$commandPart2 = decode('222929293b');" fullword ascii
    $s8 = "for ($i = 0, $n = strlen($stringToDecode); $i < $n; $i+= 2) {" fullword ascii
    $s9 = "$output.= pack('H*', substr($stringToDecode, $i, 2));" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}