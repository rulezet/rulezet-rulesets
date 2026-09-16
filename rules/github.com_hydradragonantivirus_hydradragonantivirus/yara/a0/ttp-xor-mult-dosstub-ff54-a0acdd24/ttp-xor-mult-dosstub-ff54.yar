rule TTP_XOR_MULT_DOSStub_ff54 {
  strings:
    $key_ff54 = { ab 3c [2] df 24 [2] 98 26 [2] df 37 [2] 91 3b [2] 9d 31 [2] 8a 3a [2] 91 74 [2] ac }

  condition:
    any of them
}