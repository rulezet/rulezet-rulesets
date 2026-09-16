rule TTP_XOR_MULT_DOSStub_ff46 {
  strings:
    $key_ff46 = { ab 2e [2] df 36 [2] 98 34 [2] df 25 [2] 91 29 [2] 9d 23 [2] 8a 28 [2] 91 66 [2] ac }

  condition:
    any of them
}