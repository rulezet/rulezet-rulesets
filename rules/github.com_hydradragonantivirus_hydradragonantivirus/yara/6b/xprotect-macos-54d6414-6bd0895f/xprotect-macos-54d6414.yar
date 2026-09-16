rule XProtect_MACOS_54d6414 {
  meta:
    description = "MACOS.54d6414"

  strings:
    $a = "#!"

    $b1 = "mktemp"
    $b2 = "tail -c \""
    $b3 = "funzip -\""
    $b4 = "chmod +x"
    $b5 = "nohup"

    $c1 = { 50 4b 03 04 }

  condition:
    filesize < 100KB and $a at 0 and (all of ($b*)) and $c1
}