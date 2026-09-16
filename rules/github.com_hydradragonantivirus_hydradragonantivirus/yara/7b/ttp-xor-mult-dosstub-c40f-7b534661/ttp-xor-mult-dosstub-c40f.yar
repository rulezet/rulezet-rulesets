rule TTP_XOR_MULT_DOSStub_c40f {
  strings:
    $key_c40f = { 90 67 [2] e4 7f [2] a3 7d [2] e4 6c [2] aa 60 [2] a6 6a [2] b1 61 [2] aa 2f [2] 97 }

  condition:
    any of them
}