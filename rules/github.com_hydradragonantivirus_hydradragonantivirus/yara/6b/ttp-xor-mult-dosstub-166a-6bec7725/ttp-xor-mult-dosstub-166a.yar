rule TTP_XOR_MULT_DOSStub_166a {
  strings:
    $key_166a = { 42 02 [2] 36 1a [2] 71 18 [2] 36 09 [2] 78 05 [2] 74 0f [2] 63 04 [2] 78 4a [2] 45 }

  condition:
    any of them
}