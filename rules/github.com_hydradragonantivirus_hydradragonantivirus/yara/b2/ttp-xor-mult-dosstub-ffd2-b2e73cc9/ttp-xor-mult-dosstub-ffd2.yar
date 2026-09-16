rule TTP_XOR_MULT_DOSStub_ffd2 {
  strings:
    $key_ffd2 = { ab ba [2] df a2 [2] 98 a0 [2] df b1 [2] 91 bd [2] 9d b7 [2] 8a bc [2] 91 f2 [2] ac }

  condition:
    any of them
}