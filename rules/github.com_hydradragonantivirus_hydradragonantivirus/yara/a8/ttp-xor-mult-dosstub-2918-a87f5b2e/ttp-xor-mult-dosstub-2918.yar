rule TTP_XOR_MULT_DOSStub_2918 {
  strings:
    $key_2918 = { 7d 70 [2] 09 68 [2] 4e 6a [2] 09 7b [2] 47 77 [2] 4b 7d [2] 5c 76 [2] 47 38 [2] 7a }

  condition:
    any of them
}