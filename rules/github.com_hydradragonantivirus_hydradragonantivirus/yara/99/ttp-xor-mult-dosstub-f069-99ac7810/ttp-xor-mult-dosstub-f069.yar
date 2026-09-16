rule TTP_XOR_MULT_DOSStub_f069 {
  strings:
    $key_f069 = { a4 01 [2] d0 19 [2] 97 1b [2] d0 0a [2] 9e 06 [2] 92 0c [2] 85 07 [2] 9e 49 [2] a3 }

  condition:
    any of them
}