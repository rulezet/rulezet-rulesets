rule _20160921_18f3e0383dae972ccd3326bfeb339081_20160921_9c9fcc818a70_4559 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3e0383dae972ccd3326bfeb339081.js, 20160921_9c9fcc818a7064d7449eec45fbad08d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "350a94fd53479bde96c18236897fe9846647bd4d4471ff812cc45a165d90a9d0"
    hash2       = "988df854145081fce0af79178c78ce75ca8d89b6666ec2e052b7f8de43bb1101"

  strings:
    $s1 = "f000(){return \"ZGq\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj" ascii
    $s2 = "){return \"Sq\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s3 = "{return \"UEg\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yz\";})(" ascii
    $s4 = "on f000(){return \"Br\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"" ascii
    $s5 = "f000(){return \"Tn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WI" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}