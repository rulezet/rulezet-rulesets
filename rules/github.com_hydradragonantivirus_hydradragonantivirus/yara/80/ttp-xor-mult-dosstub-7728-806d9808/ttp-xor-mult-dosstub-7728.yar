rule TTP_XOR_MULT_DOSStub_7728 {
  strings:
    $key_7728 = { 23 40 [2] 57 58 [2] 10 5a [2] 57 4b [2] 19 47 [2] 15 4d [2] 02 46 [2] 19 08 [2] 24 }

  condition:
    any of them
}