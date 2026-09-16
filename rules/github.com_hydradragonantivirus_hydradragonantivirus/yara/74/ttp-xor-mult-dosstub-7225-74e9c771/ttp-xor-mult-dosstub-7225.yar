rule TTP_XOR_MULT_DOSStub_7225 {
  strings:
    $key_7225 = { 26 4d [2] 52 55 [2] 15 57 [2] 52 46 [2] 1c 4a [2] 10 40 [2] 07 4b [2] 1c 05 [2] 21 }

  condition:
    any of them
}