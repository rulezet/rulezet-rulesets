rule TTP_XOR_MULT_DOSStub_3c25 {
  strings:
    $key_3c25 = { 68 4d [2] 1c 55 [2] 5b 57 [2] 1c 46 [2] 52 4a [2] 5e 40 [2] 49 4b [2] 52 05 [2] 6f }

  condition:
    any of them
}