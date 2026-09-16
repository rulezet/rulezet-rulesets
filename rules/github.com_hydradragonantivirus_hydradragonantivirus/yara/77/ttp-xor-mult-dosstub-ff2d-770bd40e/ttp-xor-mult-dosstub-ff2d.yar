rule TTP_XOR_MULT_DOSStub_ff2d {
  strings:
    $key_ff2d = { ab 45 [2] df 5d [2] 98 5f [2] df 4e [2] 91 42 [2] 9d 48 [2] 8a 43 [2] 91 0d [2] ac }

  condition:
    any of them
}