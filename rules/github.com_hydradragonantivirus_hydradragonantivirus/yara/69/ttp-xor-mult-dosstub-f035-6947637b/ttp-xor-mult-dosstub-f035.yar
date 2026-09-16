rule TTP_XOR_MULT_DOSStub_f035 {
  strings:
    $key_f035 = { a4 5d [2] d0 45 [2] 97 47 [2] d0 56 [2] 9e 5a [2] 92 50 [2] 85 5b [2] 9e 15 [2] a3 }

  condition:
    any of them
}