rule TTP_XOR_MULT_DOSStub_43ea {
  strings:
    $key_43ea = { 17 82 [2] 63 9a [2] 24 98 [2] 63 89 [2] 2d 85 [2] 21 8f [2] 36 84 [2] 2d ca [2] 10 }

  condition:
    any of them
}