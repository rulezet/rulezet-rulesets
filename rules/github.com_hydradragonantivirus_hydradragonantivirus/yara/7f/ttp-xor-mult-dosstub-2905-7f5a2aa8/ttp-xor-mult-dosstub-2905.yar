rule TTP_XOR_MULT_DOSStub_2905 {
  strings:
    $key_2905 = { 7d 6d [2] 09 75 [2] 4e 77 [2] 09 66 [2] 47 6a [2] 4b 60 [2] 5c 6b [2] 47 25 [2] 7a }

  condition:
    any of them
}