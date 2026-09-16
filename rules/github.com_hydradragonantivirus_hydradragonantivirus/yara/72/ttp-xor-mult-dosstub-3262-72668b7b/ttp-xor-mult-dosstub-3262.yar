rule TTP_XOR_MULT_DOSStub_3262 {
  strings:
    $key_3262 = { 66 0a [2] 12 12 [2] 55 10 [2] 12 01 [2] 5c 0d [2] 50 07 [2] 47 0c [2] 5c 42 [2] 61 }

  condition:
    any of them
}