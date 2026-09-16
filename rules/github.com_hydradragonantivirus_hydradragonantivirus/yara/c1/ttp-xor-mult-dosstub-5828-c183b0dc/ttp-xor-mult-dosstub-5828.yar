rule TTP_XOR_MULT_DOSStub_5828 {
  strings:
    $key_5828 = { 0c 40 [2] 78 58 [2] 3f 5a [2] 78 4b [2] 36 47 [2] 3a 4d [2] 2d 46 [2] 36 08 [2] 0b }

  condition:
    any of them
}