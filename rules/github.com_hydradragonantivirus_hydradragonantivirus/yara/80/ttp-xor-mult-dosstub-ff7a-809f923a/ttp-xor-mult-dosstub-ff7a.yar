rule TTP_XOR_MULT_DOSStub_ff7a {
  strings:
    $key_ff7a = { ab 12 [2] df 0a [2] 98 08 [2] df 19 [2] 91 15 [2] 9d 1f [2] 8a 14 [2] 91 5a [2] ac }

  condition:
    any of them
}