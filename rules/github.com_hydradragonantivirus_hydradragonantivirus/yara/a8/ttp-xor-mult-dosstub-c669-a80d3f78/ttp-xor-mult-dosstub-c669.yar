rule TTP_XOR_MULT_DOSStub_c669 {
  strings:
    $key_c669 = { 92 01 [2] e6 19 [2] a1 1b [2] e6 0a [2] a8 06 [2] a4 0c [2] b3 07 [2] a8 49 [2] 95 }

  condition:
    any of them
}