rule TTP_XOR_MULT_DOSStub_65ea {
  strings:
    $key_65ea = { 31 82 [2] 45 9a [2] 02 98 [2] 45 89 [2] 0b 85 [2] 07 8f [2] 10 84 [2] 0b ca [2] 36 }

  condition:
    any of them
}