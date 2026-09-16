rule TTP_XOR_MULT_DOSStub_ffd3 {
  strings:
    $key_ffd3 = { ab bb [2] df a3 [2] 98 a1 [2] df b0 [2] 91 bc [2] 9d b6 [2] 8a bd [2] 91 f3 [2] ac }

  condition:
    any of them
}