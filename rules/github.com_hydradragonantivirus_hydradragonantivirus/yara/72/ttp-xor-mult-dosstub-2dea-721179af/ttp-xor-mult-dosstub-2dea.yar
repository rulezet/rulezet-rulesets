rule TTP_XOR_MULT_DOSStub_2dea {
  strings:
    $key_2dea = { 79 82 [2] 0d 9a [2] 4a 98 [2] 0d 89 [2] 43 85 [2] 4f 8f [2] 58 84 [2] 43 ca [2] 7e }

  condition:
    any of them
}