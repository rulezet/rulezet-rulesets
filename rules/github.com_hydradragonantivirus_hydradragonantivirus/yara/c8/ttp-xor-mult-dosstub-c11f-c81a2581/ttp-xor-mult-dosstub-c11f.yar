rule TTP_XOR_MULT_DOSStub_c11f {
  strings:
    $key_c11f = { 95 77 [2] e1 6f [2] a6 6d [2] e1 7c [2] af 70 [2] a3 7a [2] b4 71 [2] af 3f [2] 92 }

  condition:
    any of them
}