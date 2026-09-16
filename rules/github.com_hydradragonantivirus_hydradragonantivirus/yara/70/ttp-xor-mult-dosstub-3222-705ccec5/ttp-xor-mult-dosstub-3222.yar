rule TTP_XOR_MULT_DOSStub_3222 {
  strings:
    $key_3222 = { 66 4a [2] 12 52 [2] 55 50 [2] 12 41 [2] 5c 4d [2] 50 47 [2] 47 4c [2] 5c 02 [2] 61 }

  condition:
    any of them
}