rule TTP_XOR_MULT_DOSStub_6b25 {
  strings:
    $key_6b25 = { 3f 4d [2] 4b 55 [2] 0c 57 [2] 4b 46 [2] 05 4a [2] 09 40 [2] 1e 4b [2] 05 05 [2] 38 }

  condition:
    any of them
}