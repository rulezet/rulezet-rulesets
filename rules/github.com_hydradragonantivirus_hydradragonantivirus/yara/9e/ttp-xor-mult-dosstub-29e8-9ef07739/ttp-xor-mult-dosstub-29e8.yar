rule TTP_XOR_MULT_DOSStub_29e8 {
  strings:
    $key_29e8 = { 7d 80 [2] 09 98 [2] 4e 9a [2] 09 8b [2] 47 87 [2] 4b 8d [2] 5c 86 [2] 47 c8 [2] 7a }

  condition:
    any of them
}