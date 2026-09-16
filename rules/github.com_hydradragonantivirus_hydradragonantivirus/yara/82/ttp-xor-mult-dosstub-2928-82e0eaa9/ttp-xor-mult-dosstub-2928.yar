rule TTP_XOR_MULT_DOSStub_2928 {
  strings:
    $key_2928 = { 7d 40 [2] 09 58 [2] 4e 5a [2] 09 4b [2] 47 47 [2] 4b 4d [2] 5c 46 [2] 47 08 [2] 7a }

  condition:
    any of them
}