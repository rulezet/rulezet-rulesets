rule TTP_XOR_MULT_DOSStub_ffb1 {
  strings:
    $key_ffb1 = { ab d9 [2] df c1 [2] 98 c3 [2] df d2 [2] 91 de [2] 9d d4 [2] 8a df [2] 91 91 [2] ac }

  condition:
    any of them
}