rule TTP_XOR_MULT_DOSStub_13ea {
  strings:
    $key_13ea = { 47 82 [2] 33 9a [2] 74 98 [2] 33 89 [2] 7d 85 [2] 71 8f [2] 66 84 [2] 7d ca [2] 40 }

  condition:
    any of them
}