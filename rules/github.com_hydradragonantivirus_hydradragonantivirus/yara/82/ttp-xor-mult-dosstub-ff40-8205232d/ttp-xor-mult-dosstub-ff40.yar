rule TTP_XOR_MULT_DOSStub_ff40 {
  strings:
    $key_ff40 = { ab 28 [2] df 30 [2] 98 32 [2] df 23 [2] 91 2f [2] 9d 25 [2] 8a 2e [2] 91 60 [2] ac }

  condition:
    any of them
}