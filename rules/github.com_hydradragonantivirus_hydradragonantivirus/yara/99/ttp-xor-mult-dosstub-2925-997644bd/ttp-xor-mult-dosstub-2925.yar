rule TTP_XOR_MULT_DOSStub_2925 {
  strings:
    $key_2925 = { 7d 4d [2] 09 55 [2] 4e 57 [2] 09 46 [2] 47 4a [2] 4b 40 [2] 5c 4b [2] 47 05 [2] 7a }

  condition:
    any of them
}