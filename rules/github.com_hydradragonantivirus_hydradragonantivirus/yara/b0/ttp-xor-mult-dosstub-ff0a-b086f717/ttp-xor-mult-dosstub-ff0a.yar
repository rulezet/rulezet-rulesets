rule TTP_XOR_MULT_DOSStub_ff0a {
  strings:
    $key_ff0a = { ab 62 [2] df 7a [2] 98 78 [2] df 69 [2] 91 65 [2] 9d 6f [2] 8a 64 [2] 91 2a [2] ac }

  condition:
    any of them
}