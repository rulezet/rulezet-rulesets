rule TTP_XOR_MULT_DOSStub_3025 {
  strings:
    $key_3025 = { 64 4d [2] 10 55 [2] 57 57 [2] 10 46 [2] 5e 4a [2] 52 40 [2] 45 4b [2] 5e 05 [2] 63 }

  condition:
    any of them
}