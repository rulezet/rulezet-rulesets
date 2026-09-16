rule TTP_XOR_MULT_DOSStub_ff16 {
  strings:
    $key_ff16 = { ab 7e [2] df 66 [2] 98 64 [2] df 75 [2] 91 79 [2] 9d 73 [2] 8a 78 [2] 91 36 [2] ac }

  condition:
    any of them
}