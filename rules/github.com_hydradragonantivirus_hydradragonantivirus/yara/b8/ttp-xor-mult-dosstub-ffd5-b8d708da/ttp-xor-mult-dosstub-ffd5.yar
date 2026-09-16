rule TTP_XOR_MULT_DOSStub_ffd5 {
  strings:
    $key_ffd5 = { ab bd [2] df a5 [2] 98 a7 [2] df b6 [2] 91 ba [2] 9d b0 [2] 8a bb [2] 91 f5 [2] ac }

  condition:
    any of them
}