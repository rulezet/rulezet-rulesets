rule TTP_XOR_MULT_DOSStub_ff12 {
  strings:
    $key_ff12 = { ab 7a [2] df 62 [2] 98 60 [2] df 71 [2] 91 7d [2] 9d 77 [2] 8a 7c [2] 91 32 [2] ac }

  condition:
    any of them
}