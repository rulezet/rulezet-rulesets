rule TTP_XOR_MULT_DOSStub_3ce2 {
  strings:
    $key_3ce2 = { 68 8a [2] 1c 92 [2] 5b 90 [2] 1c 81 [2] 52 8d [2] 5e 87 [2] 49 8c [2] 52 c2 [2] 6f }

  condition:
    any of them
}