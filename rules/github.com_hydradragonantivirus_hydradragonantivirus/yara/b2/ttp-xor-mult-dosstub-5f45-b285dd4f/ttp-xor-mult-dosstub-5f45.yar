rule TTP_XOR_MULT_DOSStub_5f45 {
  strings:
    $key_5f45 = { 0b 2d [2] 7f 35 [2] 38 37 [2] 7f 26 [2] 31 2a [2] 3d 20 [2] 2a 2b [2] 31 65 [2] 0c }

  condition:
    any of them
}