rule TTP_XOR_MULT_DOSStub_29f5 {
  strings:
    $key_29f5 = { 7d 9d [2] 09 85 [2] 4e 87 [2] 09 96 [2] 47 9a [2] 4b 90 [2] 5c 9b [2] 47 d5 [2] 7a }

  condition:
    any of them
}