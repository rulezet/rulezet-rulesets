rule TTP_XOR_MULT_DOSStub_49ea {
  strings:
    $key_49ea = { 1d 82 [2] 69 9a [2] 2e 98 [2] 69 89 [2] 27 85 [2] 2b 8f [2] 3c 84 [2] 27 ca [2] 1a }

  condition:
    any of them
}