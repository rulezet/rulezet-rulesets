rule TTP_XOR_MULT_DOSStub_00e5 {
  strings:
    $key_00e5 = { 54 8d [2] 20 95 [2] 67 97 [2] 20 86 [2] 6e 8a [2] 62 80 [2] 75 8b [2] 6e c5 [2] 53 }

  condition:
    any of them
}