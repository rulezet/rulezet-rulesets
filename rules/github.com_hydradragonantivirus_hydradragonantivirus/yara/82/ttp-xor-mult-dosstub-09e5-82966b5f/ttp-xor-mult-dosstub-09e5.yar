rule TTP_XOR_MULT_DOSStub_09e5 {
  strings:
    $key_09e5 = { 5d 8d [2] 29 95 [2] 6e 97 [2] 29 86 [2] 67 8a [2] 6b 80 [2] 7c 8b [2] 67 c5 [2] 5a }

  condition:
    any of them
}