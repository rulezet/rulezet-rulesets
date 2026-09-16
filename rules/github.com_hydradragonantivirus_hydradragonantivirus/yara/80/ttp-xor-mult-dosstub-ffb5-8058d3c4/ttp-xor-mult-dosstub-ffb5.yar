rule TTP_XOR_MULT_DOSStub_ffb5 {
  strings:
    $key_ffb5 = { ab dd [2] df c5 [2] 98 c7 [2] df d6 [2] 91 da [2] 9d d0 [2] 8a db [2] 91 95 [2] ac }

  condition:
    any of them
}