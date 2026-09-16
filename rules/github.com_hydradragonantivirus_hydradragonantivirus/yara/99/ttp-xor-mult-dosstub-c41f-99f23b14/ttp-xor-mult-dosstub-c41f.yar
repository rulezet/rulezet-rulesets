rule TTP_XOR_MULT_DOSStub_c41f {
  strings:
    $key_c41f = { 90 77 [2] e4 6f [2] a3 6d [2] e4 7c [2] aa 70 [2] a6 7a [2] b1 71 [2] aa 3f [2] 97 }

  condition:
    any of them
}