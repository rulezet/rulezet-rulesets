rule TTP_XOR_MULT_DOSStub_ffb6 {
  strings:
    $key_ffb6 = { ab de [2] df c6 [2] 98 c4 [2] df d5 [2] 91 d9 [2] 9d d3 [2] 8a d8 [2] 91 96 [2] ac }

  condition:
    any of them
}