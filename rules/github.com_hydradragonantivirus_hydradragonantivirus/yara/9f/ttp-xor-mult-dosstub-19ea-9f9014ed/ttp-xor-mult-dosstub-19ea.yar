rule TTP_XOR_MULT_DOSStub_19ea {
  strings:
    $key_19ea = { 4d 82 [2] 39 9a [2] 7e 98 [2] 39 89 [2] 77 85 [2] 7b 8f [2] 6c 84 [2] 77 ca [2] 4a }

  condition:
    any of them
}