rule TTP_XOR_MULT_DOSStub_2e79 {
  strings:
    $key_2e79 = { 7a 11 [2] 0e 09 [2] 49 0b [2] 0e 1a [2] 40 16 [2] 4c 1c [2] 5b 17 [2] 40 59 [2] 7d }

  condition:
    any of them
}