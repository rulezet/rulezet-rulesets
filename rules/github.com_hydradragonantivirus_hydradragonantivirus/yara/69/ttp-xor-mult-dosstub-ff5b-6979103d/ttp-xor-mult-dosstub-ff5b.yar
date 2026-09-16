rule TTP_XOR_MULT_DOSStub_ff5b {
  strings:
    $key_ff5b = { ab 33 [2] df 2b [2] 98 29 [2] df 38 [2] 91 34 [2] 9d 3e [2] 8a 35 [2] 91 7b [2] ac }

  condition:
    any of them
}