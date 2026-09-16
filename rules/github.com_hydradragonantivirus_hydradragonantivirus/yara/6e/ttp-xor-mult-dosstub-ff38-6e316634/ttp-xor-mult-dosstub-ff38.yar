rule TTP_XOR_MULT_DOSStub_ff38 {
  strings:
    $key_ff38 = { ab 50 [2] df 48 [2] 98 4a [2] df 5b [2] 91 57 [2] 9d 5d [2] 8a 56 [2] 91 18 [2] ac }

  condition:
    any of them
}