rule TTP_XOR_MULT_DOSStub_c403 {
  strings:
    $key_c403 = { 90 6b [2] e4 73 [2] a3 71 [2] e4 60 [2] aa 6c [2] a6 66 [2] b1 6d [2] aa 23 [2] 97 }

  condition:
    any of them
}