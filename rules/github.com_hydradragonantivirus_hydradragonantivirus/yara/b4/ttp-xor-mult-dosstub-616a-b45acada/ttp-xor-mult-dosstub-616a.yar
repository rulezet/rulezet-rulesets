rule TTP_XOR_MULT_DOSStub_616a {
  strings:
    $key_616a = { 35 02 [2] 41 1a [2] 06 18 [2] 41 09 [2] 0f 05 [2] 03 0f [2] 14 04 [2] 0f 4a [2] 32 }

  condition:
    any of them
}