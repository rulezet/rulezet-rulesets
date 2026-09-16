rule TTP_XOR_MULT_DOSStub_c40e {
  strings:
    $key_c40e = { 90 66 [2] e4 7e [2] a3 7c [2] e4 6d [2] aa 61 [2] a6 6b [2] b1 60 [2] aa 2e [2] 97 }

  condition:
    any of them
}