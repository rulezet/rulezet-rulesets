rule TTP_XOR_MULT_DOSStub_ff37 {
  strings:
    $key_ff37 = { ab 5f [2] df 47 [2] 98 45 [2] df 54 [2] 91 58 [2] 9d 52 [2] 8a 59 [2] 91 17 [2] ac }

  condition:
    any of them
}