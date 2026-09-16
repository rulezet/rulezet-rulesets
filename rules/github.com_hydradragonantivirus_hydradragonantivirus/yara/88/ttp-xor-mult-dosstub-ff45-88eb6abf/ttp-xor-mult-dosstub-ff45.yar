rule TTP_XOR_MULT_DOSStub_ff45 {
  strings:
    $key_ff45 = { ab 2d [2] df 35 [2] 98 37 [2] df 26 [2] 91 2a [2] 9d 20 [2] 8a 2b [2] 91 65 [2] ac }

  condition:
    any of them
}