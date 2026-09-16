rule TTP_XOR_MULT_DOSStub_2648 {
  strings:
    $key_2648 = { 72 20 [2] 06 38 [2] 41 3a [2] 06 2b [2] 48 27 [2] 44 2d [2] 53 26 [2] 48 68 [2] 75 }

  condition:
    any of them
}