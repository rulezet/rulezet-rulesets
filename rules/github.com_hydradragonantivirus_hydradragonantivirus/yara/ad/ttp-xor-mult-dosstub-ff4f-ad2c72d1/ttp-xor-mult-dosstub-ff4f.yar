rule TTP_XOR_MULT_DOSStub_ff4f {
  strings:
    $key_ff4f = { ab 27 [2] df 3f [2] 98 3d [2] df 2c [2] 91 20 [2] 9d 2a [2] 8a 21 [2] 91 6f [2] ac }

  condition:
    any of them
}