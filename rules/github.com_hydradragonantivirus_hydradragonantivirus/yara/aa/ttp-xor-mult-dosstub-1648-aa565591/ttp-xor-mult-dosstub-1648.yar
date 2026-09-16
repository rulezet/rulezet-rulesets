rule TTP_XOR_MULT_DOSStub_1648 {
  strings:
    $key_1648 = { 42 20 [2] 36 38 [2] 71 3a [2] 36 2b [2] 78 27 [2] 74 2d [2] 63 26 [2] 78 68 [2] 45 }

  condition:
    any of them
}