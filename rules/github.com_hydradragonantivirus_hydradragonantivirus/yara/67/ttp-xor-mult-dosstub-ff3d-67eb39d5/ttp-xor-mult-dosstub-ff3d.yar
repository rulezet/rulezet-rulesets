rule TTP_XOR_MULT_DOSStub_ff3d {
  strings:
    $key_ff3d = { ab 55 [2] df 4d [2] 98 4f [2] df 5e [2] 91 52 [2] 9d 58 [2] 8a 53 [2] 91 1d [2] ac }

  condition:
    any of them
}