rule TTP_XOR_MULT_DOSStub_29e2 {
  strings:
    $key_29e2 = { 7d 8a [2] 09 92 [2] 4e 90 [2] 09 81 [2] 47 8d [2] 4b 87 [2] 5c 8c [2] 47 c2 [2] 7a }

  condition:
    any of them
}