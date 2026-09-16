rule TTP_XOR_MULT_DOSStub_29f8 {
  strings:
    $key_29f8 = { 7d 90 [2] 09 88 [2] 4e 8a [2] 09 9b [2] 47 97 [2] 4b 9d [2] 5c 96 [2] 47 d8 [2] 7a }

  condition:
    any of them
}