rule TTP_XOR_MULT_DOSStub_3971 {
  strings:
    $key_3971 = { 6d 19 [2] 19 01 [2] 5e 03 [2] 19 12 [2] 57 1e [2] 5b 14 [2] 4c 1f [2] 57 51 [2] 6a }

  condition:
    any of them
}