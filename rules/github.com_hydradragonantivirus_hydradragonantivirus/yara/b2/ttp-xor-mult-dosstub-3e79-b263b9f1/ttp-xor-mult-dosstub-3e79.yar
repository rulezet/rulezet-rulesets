rule TTP_XOR_MULT_DOSStub_3e79 {
  strings:
    $key_3e79 = { 6a 11 [2] 1e 09 [2] 59 0b [2] 1e 1a [2] 50 16 [2] 5c 1c [2] 4b 17 [2] 50 59 [2] 6d }

  condition:
    any of them
}