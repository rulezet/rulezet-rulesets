rule TTP_XOR_MULT_DOSStub_ff4e {
  strings:
    $key_ff4e = { ab 26 [2] df 3e [2] 98 3c [2] df 2d [2] 91 21 [2] 9d 2b [2] 8a 20 [2] 91 6e [2] ac }

  condition:
    any of them
}