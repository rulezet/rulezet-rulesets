rule TTP_XOR_MULT_DOSStub_5071 {
  strings:
    $key_5071 = { 04 19 [2] 70 01 [2] 37 03 [2] 70 12 [2] 3e 1e [2] 32 14 [2] 25 1f [2] 3e 51 [2] 03 }

  condition:
    any of them
}