rule TTP_XOR_MULT_DOSStub_ff42 {
  strings:
    $key_ff42 = { ab 2a [2] df 32 [2] 98 30 [2] df 21 [2] 91 2d [2] 9d 27 [2] 8a 2c [2] 91 62 [2] ac }

  condition:
    any of them
}