rule TTP_XOR_MULT_DOSStub_4815 {
  strings:
    $key_4815 = { 1c 7d [2] 68 65 [2] 2f 67 [2] 68 76 [2] 26 7a [2] 2a 70 [2] 3d 7b [2] 26 35 [2] 1b }

  condition:
    any of them
}