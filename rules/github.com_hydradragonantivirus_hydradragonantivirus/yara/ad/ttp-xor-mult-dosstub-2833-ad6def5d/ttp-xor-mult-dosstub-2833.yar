rule TTP_XOR_MULT_DOSStub_2833 {
  strings:
    $key_2833 = { 7c 5b [2] 08 43 [2] 4f 41 [2] 08 50 [2] 46 5c [2] 4a 56 [2] 5d 5d [2] 46 13 [2] 7b }

  condition:
    any of them
}