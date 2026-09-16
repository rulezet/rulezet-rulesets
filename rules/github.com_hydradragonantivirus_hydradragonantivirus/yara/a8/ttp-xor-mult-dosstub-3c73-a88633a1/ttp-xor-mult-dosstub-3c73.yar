rule TTP_XOR_MULT_DOSStub_3c73 {
  strings:
    $key_3c73 = { 68 1b [2] 1c 03 [2] 5b 01 [2] 1c 10 [2] 52 1c [2] 5e 16 [2] 49 1d [2] 52 53 [2] 6f }

  condition:
    any of them
}