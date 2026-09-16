rule TTP_XOR_MULT_DOSStub_29e5 {
  strings:
    $key_29e5 = { 7d 8d [2] 09 95 [2] 4e 97 [2] 09 86 [2] 47 8a [2] 4b 80 [2] 5c 8b [2] 47 c5 [2] 7a }

  condition:
    any of them
}