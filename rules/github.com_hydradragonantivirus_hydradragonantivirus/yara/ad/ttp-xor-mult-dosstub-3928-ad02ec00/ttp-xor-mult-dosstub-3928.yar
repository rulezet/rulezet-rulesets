rule TTP_XOR_MULT_DOSStub_3928 {
  strings:
    $key_3928 = { 6d 40 [2] 19 58 [2] 5e 5a [2] 19 4b [2] 57 47 [2] 5b 4d [2] 4c 46 [2] 57 08 [2] 6a }

  condition:
    any of them
}