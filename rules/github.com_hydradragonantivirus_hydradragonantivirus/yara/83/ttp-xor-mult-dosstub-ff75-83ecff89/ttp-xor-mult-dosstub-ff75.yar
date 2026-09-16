rule TTP_XOR_MULT_DOSStub_ff75 {
  strings:
    $key_ff75 = { ab 1d [2] df 05 [2] 98 07 [2] df 16 [2] 91 1a [2] 9d 10 [2] 8a 1b [2] 91 55 [2] ac }

  condition:
    any of them
}