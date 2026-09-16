rule TTP_XOR_MULT_DOSStub_ffe1 {
  strings:
    $key_ffe1 = { ab 89 [2] df 91 [2] 98 93 [2] df 82 [2] 91 8e [2] 9d 84 [2] 8a 8f [2] 91 c1 [2] ac }

  condition:
    any of them
}