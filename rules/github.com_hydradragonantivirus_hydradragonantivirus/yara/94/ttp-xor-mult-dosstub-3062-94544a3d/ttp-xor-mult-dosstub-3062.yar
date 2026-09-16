rule TTP_XOR_MULT_DOSStub_3062 {
  strings:
    $key_3062 = { 64 0a [2] 10 12 [2] 57 10 [2] 10 01 [2] 5e 0d [2] 52 07 [2] 45 0c [2] 5e 42 [2] 63 }

  condition:
    any of them
}