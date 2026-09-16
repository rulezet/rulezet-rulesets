rule TTP_XOR_MULT_DOSStub_ff35 {
  strings:
    $key_ff35 = { ab 5d [2] df 45 [2] 98 47 [2] df 56 [2] 91 5a [2] 9d 50 [2] 8a 5b [2] 91 15 [2] ac }

  condition:
    any of them
}