rule TTP_XOR_MULT_DOSStub_f503 {
  strings:
    $key_f503 = { a1 6b [2] d5 73 [2] 92 71 [2] d5 60 [2] 9b 6c [2] 97 66 [2] 80 6d [2] 9b 23 [2] a6 }

  condition:
    any of them
}