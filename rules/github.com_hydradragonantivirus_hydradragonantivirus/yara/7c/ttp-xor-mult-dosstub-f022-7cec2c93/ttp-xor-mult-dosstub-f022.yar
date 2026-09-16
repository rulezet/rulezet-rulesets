rule TTP_XOR_MULT_DOSStub_f022 {
  strings:
    $key_f022 = { a4 4a [2] d0 52 [2] 97 50 [2] d0 41 [2] 9e 4d [2] 92 47 [2] 85 4c [2] 9e 02 [2] a3 }

  condition:
    any of them
}