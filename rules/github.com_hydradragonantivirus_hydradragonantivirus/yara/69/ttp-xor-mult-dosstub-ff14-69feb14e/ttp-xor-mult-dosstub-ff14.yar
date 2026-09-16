rule TTP_XOR_MULT_DOSStub_ff14 {
  strings:
    $key_ff14 = { ab 7c [2] df 64 [2] 98 66 [2] df 77 [2] 91 7b [2] 9d 71 [2] 8a 7a [2] 91 34 [2] ac }

  condition:
    any of them
}