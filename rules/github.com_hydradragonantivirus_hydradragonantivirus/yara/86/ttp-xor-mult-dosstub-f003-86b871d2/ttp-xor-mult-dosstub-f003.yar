rule TTP_XOR_MULT_DOSStub_f003 {
  strings:
    $key_f003 = { a4 6b [2] d0 73 [2] 97 71 [2] d0 60 [2] 9e 6c [2] 92 66 [2] 85 6d [2] 9e 23 [2] a3 }

  condition:
    any of them
}