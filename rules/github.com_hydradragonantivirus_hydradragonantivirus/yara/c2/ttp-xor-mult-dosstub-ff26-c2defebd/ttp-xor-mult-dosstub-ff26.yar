rule TTP_XOR_MULT_DOSStub_ff26 {
  strings:
    $key_ff26 = { ab 4e [2] df 56 [2] 98 54 [2] df 45 [2] 91 49 [2] 9d 43 [2] 8a 48 [2] 91 06 [2] ac }

  condition:
    any of them
}