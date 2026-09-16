rule TTP_XOR_MULT_DOSStub_2748 {
  strings:
    $key_2748 = { 73 20 [2] 07 38 [2] 40 3a [2] 07 2b [2] 49 27 [2] 45 2d [2] 52 26 [2] 49 68 [2] 74 }

  condition:
    any of them
}