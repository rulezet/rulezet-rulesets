rule TTP_XOR_MULT_DOSStub_ff41 {
  strings:
    $key_ff41 = { ab 29 [2] df 31 [2] 98 33 [2] df 22 [2] 91 2e [2] 9d 24 [2] 8a 2f [2] 91 61 [2] ac }

  condition:
    any of them
}