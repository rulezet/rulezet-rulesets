rule TTP_XOR_MULT_DOSStub_6b38 {
  strings:
    $key_6b38 = { 3f 50 [2] 4b 48 [2] 0c 4a [2] 4b 5b [2] 05 57 [2] 09 5d [2] 1e 56 [2] 05 18 [2] 38 }

  condition:
    any of them
}