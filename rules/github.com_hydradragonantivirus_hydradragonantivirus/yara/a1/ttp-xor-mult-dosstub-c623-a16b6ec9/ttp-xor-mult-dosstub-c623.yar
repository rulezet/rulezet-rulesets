rule TTP_XOR_MULT_DOSStub_c623 {
  strings:
    $key_c623 = { 92 4b [2] e6 53 [2] a1 51 [2] e6 40 [2] a8 4c [2] a4 46 [2] b3 4d [2] a8 03 [2] 95 }

  condition:
    any of them
}