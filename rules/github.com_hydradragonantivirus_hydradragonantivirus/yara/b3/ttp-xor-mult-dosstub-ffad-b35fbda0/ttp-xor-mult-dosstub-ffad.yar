rule TTP_XOR_MULT_DOSStub_ffad {
  strings:
    $key_ffad = { ab c5 [2] df dd [2] 98 df [2] df ce [2] 91 c2 [2] 9d c8 [2] 8a c3 [2] 91 8d [2] ac }

  condition:
    any of them
}