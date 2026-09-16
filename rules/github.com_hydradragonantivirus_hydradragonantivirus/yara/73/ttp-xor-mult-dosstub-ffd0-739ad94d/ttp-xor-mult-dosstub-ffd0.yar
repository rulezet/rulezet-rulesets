rule TTP_XOR_MULT_DOSStub_ffd0 {
  strings:
    $key_ffd0 = { ab b8 [2] df a0 [2] 98 a2 [2] df b3 [2] 91 bf [2] 9d b5 [2] 8a be [2] 91 f0 [2] ac }

  condition:
    any of them
}