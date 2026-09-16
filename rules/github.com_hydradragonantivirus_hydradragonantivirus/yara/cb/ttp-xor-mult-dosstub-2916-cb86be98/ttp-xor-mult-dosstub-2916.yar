rule TTP_XOR_MULT_DOSStub_2916 {
  strings:
    $key_2916 = { 7d 7e [2] 09 66 [2] 4e 64 [2] 09 75 [2] 47 79 [2] 4b 73 [2] 5c 78 [2] 47 36 [2] 7a }

  condition:
    any of them
}