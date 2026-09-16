rule TTP_XOR_MULT_DOSStub_5e79 {
  strings:
    $key_5e79 = { 0a 11 [2] 7e 09 [2] 39 0b [2] 7e 1a [2] 30 16 [2] 3c 1c [2] 2b 17 [2] 30 59 [2] 0d }

  condition:
    any of them
}