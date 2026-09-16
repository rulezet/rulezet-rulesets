rule TTP_XOR_MULT_DOSStub_ff7d {
  strings:
    $key_ff7d = { ab 15 [2] df 0d [2] 98 0f [2] df 1e [2] 91 12 [2] 9d 18 [2] 8a 13 [2] 91 5d [2] ac }

  condition:
    any of them
}