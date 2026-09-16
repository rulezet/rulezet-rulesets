rule TTP_XOR_MULT_DOSStub_ffc2 {
  strings:
    $key_ffc2 = { ab aa [2] df b2 [2] 98 b0 [2] df a1 [2] 91 ad [2] 9d a7 [2] 8a ac [2] 91 e2 [2] ac }

  condition:
    any of them
}