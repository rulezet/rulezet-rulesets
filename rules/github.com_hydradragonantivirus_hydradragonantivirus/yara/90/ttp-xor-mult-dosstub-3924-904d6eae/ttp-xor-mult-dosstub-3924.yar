rule TTP_XOR_MULT_DOSStub_3924 {
  strings:
    $key_3924 = { 6d 4c [2] 19 54 [2] 5e 56 [2] 19 47 [2] 57 4b [2] 5b 41 [2] 4c 4a [2] 57 04 [2] 6a }

  condition:
    any of them
}