rule TTP_XOR_MULT_DOSStub_ffc0 {
  strings:
    $key_ffc0 = { ab a8 [2] df b0 [2] 98 b2 [2] df a3 [2] 91 af [2] 9d a5 [2] 8a ae [2] 91 e0 [2] ac }

  condition:
    any of them
}