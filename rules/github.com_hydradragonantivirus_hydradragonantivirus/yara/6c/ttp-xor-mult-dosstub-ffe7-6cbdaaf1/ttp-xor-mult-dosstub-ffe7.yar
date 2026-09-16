rule TTP_XOR_MULT_DOSStub_ffe7 {
  strings:
    $key_ffe7 = { ab 8f [2] df 97 [2] 98 95 [2] df 84 [2] 91 88 [2] 9d 82 [2] 8a 89 [2] 91 c7 [2] ac }

  condition:
    any of them
}