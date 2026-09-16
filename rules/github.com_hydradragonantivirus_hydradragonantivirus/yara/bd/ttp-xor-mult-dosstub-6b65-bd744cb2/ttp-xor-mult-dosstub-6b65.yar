rule TTP_XOR_MULT_DOSStub_6b65 {
  strings:
    $key_6b65 = { 3f 0d [2] 4b 15 [2] 0c 17 [2] 4b 06 [2] 05 0a [2] 09 00 [2] 1e 0b [2] 05 45 [2] 38 }

  condition:
    any of them
}