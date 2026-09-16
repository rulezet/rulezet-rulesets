rule TTP_XOR_MULT_DOSStub_ff6d {
  strings:
    $key_ff6d = { ab 05 [2] df 1d [2] 98 1f [2] df 0e [2] 91 02 [2] 9d 08 [2] 8a 03 [2] 91 4d [2] ac }

  condition:
    any of them
}