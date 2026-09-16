rule TTP_XOR_MULT_DOSStub_7e68 {
  strings:
    $key_7e68 = { 2a 00 [2] 5e 18 [2] 19 1a [2] 5e 0b [2] 10 07 [2] 1c 0d [2] 0b 06 [2] 10 48 [2] 2d }

  condition:
    any of them
}