rule TTP_XOR_MULT_DOSStub_336a {
  strings:
    $key_336a = { 67 02 [2] 13 1a [2] 54 18 [2] 13 09 [2] 5d 05 [2] 51 0f [2] 46 04 [2] 5d 4a [2] 60 }

  condition:
    any of them
}