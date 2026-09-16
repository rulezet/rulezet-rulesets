rule TTP_XOR_MULT_DOSStub_ff1d {
  strings:
    $key_ff1d = { ab 75 [2] df 6d [2] 98 6f [2] df 7e [2] 91 72 [2] 9d 78 [2] 8a 73 [2] 91 3d [2] ac }

  condition:
    any of them
}