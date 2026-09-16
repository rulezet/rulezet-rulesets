rule DES__32_big_AND_ {
  strings:
    $a0 = { 0f 0f 0f 0f [0-20] 00 00 ff ff [0-20] 33 33 33 33 [0-20] 00 ff 00 ff [0-20] 55 55 55 55 }

  condition:
    $a0
}