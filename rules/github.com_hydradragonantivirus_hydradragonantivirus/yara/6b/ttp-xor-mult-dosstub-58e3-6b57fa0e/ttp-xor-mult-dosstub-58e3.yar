rule TTP_XOR_MULT_DOSStub_58e3 {
  strings:
    $key_58e3 = { 0c 8b [2] 78 93 [2] 3f 91 [2] 78 80 [2] 36 8c [2] 3a 86 [2] 2d 8d [2] 36 c3 [2] 0b }

  condition:
    any of them
}