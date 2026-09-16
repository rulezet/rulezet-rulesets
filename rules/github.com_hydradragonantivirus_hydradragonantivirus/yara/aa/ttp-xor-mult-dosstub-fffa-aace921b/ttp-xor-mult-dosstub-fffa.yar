rule TTP_XOR_MULT_DOSStub_fffa {
  strings:
    $key_fffa = { ab 92 [2] df 8a [2] 98 88 [2] df 99 [2] 91 95 [2] 9d 9f [2] 8a 94 [2] 91 da [2] ac }

  condition:
    any of them
}