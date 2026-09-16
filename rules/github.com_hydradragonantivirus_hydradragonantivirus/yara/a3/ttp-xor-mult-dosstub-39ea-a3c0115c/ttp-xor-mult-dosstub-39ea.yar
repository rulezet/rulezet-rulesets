rule TTP_XOR_MULT_DOSStub_39ea {
  strings:
    $key_39ea = { 6d 82 [2] 19 9a [2] 5e 98 [2] 19 89 [2] 57 85 [2] 5b 8f [2] 4c 84 [2] 57 ca [2] 6a }

  condition:
    any of them
}