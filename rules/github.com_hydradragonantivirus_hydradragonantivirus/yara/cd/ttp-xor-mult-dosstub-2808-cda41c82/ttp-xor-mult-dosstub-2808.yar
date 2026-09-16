rule TTP_XOR_MULT_DOSStub_2808 {
  strings:
    $key_2808 = { 7c 60 [2] 08 78 [2] 4f 7a [2] 08 6b [2] 46 67 [2] 4a 6d [2] 5d 66 [2] 46 28 [2] 7b }

  condition:
    any of them
}