rule TTP_XOR_MULT_DOSStub_1cea {
  strings:
    $key_1cea = { 48 82 [2] 3c 9a [2] 7b 98 [2] 3c 89 [2] 72 85 [2] 7e 8f [2] 69 84 [2] 72 ca [2] 4f }

  condition:
    any of them
}