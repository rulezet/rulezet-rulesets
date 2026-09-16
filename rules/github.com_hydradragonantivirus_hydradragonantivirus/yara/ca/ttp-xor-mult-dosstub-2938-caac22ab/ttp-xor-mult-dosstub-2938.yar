rule TTP_XOR_MULT_DOSStub_2938 {
  strings:
    $key_2938 = { 7d 50 [2] 09 48 [2] 4e 4a [2] 09 5b [2] 47 57 [2] 4b 5d [2] 5c 56 [2] 47 18 [2] 7a }

  condition:
    any of them
}