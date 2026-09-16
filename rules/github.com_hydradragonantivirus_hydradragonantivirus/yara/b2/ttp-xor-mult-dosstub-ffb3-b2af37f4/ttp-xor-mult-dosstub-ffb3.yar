rule TTP_XOR_MULT_DOSStub_ffb3 {
  strings:
    $key_ffb3 = { ab db [2] df c3 [2] 98 c1 [2] df d0 [2] 91 dc [2] 9d d6 [2] 8a dd [2] 91 93 [2] ac }

  condition:
    any of them
}