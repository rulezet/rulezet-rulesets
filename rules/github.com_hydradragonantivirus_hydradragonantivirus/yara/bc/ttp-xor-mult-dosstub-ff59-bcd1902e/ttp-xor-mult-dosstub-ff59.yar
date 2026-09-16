rule TTP_XOR_MULT_DOSStub_ff59 {
  strings:
    $key_ff59 = { ab 31 [2] df 29 [2] 98 2b [2] df 3a [2] 91 36 [2] 9d 3c [2] 8a 37 [2] 91 79 [2] ac }

  condition:
    any of them
}