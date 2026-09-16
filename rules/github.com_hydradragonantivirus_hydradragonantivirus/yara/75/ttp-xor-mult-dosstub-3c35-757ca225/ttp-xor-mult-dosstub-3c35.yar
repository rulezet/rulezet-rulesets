rule TTP_XOR_MULT_DOSStub_3c35 {
  strings:
    $key_3c35 = { 68 5d [2] 1c 45 [2] 5b 47 [2] 1c 56 [2] 52 5a [2] 5e 50 [2] 49 5b [2] 52 15 [2] 6f }

  condition:
    any of them
}