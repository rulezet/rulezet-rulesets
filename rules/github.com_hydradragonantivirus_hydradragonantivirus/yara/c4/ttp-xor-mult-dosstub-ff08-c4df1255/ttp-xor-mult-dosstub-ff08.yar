rule TTP_XOR_MULT_DOSStub_ff08 {
  strings:
    $key_ff08 = { ab 60 [2] df 78 [2] 98 7a [2] df 6b [2] 91 67 [2] 9d 6d [2] 8a 66 [2] 91 28 [2] ac }

  condition:
    any of them
}