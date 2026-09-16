rule TTP_XOR_MULT_DOSStub_ff11 {
  strings:
    $key_ff11 = { ab 79 [2] df 61 [2] 98 63 [2] df 72 [2] 91 7e [2] 9d 74 [2] 8a 7f [2] 91 31 [2] ac }

  condition:
    any of them
}