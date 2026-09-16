rule TTP_XOR_MULT_DOSStub_ff5a {
  strings:
    $key_ff5a = { ab 32 [2] df 2a [2] 98 28 [2] df 39 [2] 91 35 [2] 9d 3f [2] 8a 34 [2] 91 7a [2] ac }

  condition:
    any of them
}