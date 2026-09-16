rule TTP_XOR_MULT_DOSStub_29f7 {
  strings:
    $key_29f7 = { 7d 9f [2] 09 87 [2] 4e 85 [2] 09 94 [2] 47 98 [2] 4b 92 [2] 5c 99 [2] 47 d7 [2] 7a }

  condition:
    any of them
}