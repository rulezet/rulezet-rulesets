rule TTP_XOR_MULT_DOSStub_3c28 {
  strings:
    $key_3c28 = { 68 40 [2] 1c 58 [2] 5b 5a [2] 1c 4b [2] 52 47 [2] 5e 4d [2] 49 46 [2] 52 08 [2] 6f }

  condition:
    any of them
}