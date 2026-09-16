rule TTP_XOR_MULT_DOSStub_6b75 {
  strings:
    $key_6b75 = { 3f 1d [2] 4b 05 [2] 0c 07 [2] 4b 16 [2] 05 1a [2] 09 10 [2] 1e 1b [2] 05 55 [2] 38 }

  condition:
    any of them
}