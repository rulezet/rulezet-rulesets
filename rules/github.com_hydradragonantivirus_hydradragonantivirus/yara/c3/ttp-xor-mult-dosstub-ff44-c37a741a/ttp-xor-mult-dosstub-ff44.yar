rule TTP_XOR_MULT_DOSStub_ff44 {
  strings:
    $key_ff44 = { ab 2c [2] df 34 [2] 98 36 [2] df 27 [2] 91 2b [2] 9d 21 [2] 8a 2a [2] 91 64 [2] ac }

  condition:
    any of them
}