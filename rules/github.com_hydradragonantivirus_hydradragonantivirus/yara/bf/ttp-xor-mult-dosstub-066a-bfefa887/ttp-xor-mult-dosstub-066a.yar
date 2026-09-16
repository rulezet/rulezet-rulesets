rule TTP_XOR_MULT_DOSStub_066a {
  strings:
    $key_066a = { 52 02 [2] 26 1a [2] 61 18 [2] 26 09 [2] 68 05 [2] 64 0f [2] 73 04 [2] 68 4a [2] 55 }

  condition:
    any of them
}