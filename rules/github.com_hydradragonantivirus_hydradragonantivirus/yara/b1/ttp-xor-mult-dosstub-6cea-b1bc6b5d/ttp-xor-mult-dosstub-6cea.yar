rule TTP_XOR_MULT_DOSStub_6cea {
  strings:
    $key_6cea = { 38 82 [2] 4c 9a [2] 0b 98 [2] 4c 89 [2] 02 85 [2] 0e 8f [2] 19 84 [2] 02 ca [2] 3f }

  condition:
    any of them
}