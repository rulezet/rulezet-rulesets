rule TTP_XOR_MULT_DOSStub_ff58 {
  strings:
    $key_ff58 = { ab 30 [2] df 28 [2] 98 2a [2] df 3b [2] 91 37 [2] 9d 3d [2] 8a 36 [2] 91 78 [2] ac }

  condition:
    any of them
}