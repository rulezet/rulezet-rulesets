rule TTP_XOR_MULT_DOSStub_ff4a {
  strings:
    $key_ff4a = { ab 22 [2] df 3a [2] 98 38 [2] df 29 [2] 91 25 [2] 9d 2f [2] 8a 24 [2] 91 6a [2] ac }

  condition:
    any of them
}