rule TTP_XOR_MULT_DOSStub_ff34 {
  strings:
    $key_ff34 = { ab 5c [2] df 44 [2] 98 46 [2] df 57 [2] 91 5b [2] 9d 51 [2] 8a 5a [2] 91 14 [2] ac }

  condition:
    any of them
}