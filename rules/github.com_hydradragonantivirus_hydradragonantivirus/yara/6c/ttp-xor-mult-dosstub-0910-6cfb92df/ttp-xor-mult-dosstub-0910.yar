rule TTP_XOR_MULT_DOSStub_0910 {
  strings:
    $key_0910 = { 5d 78 [2] 29 60 [2] 6e 62 [2] 29 73 [2] 67 7f [2] 6b 75 [2] 7c 7e [2] 67 30 [2] 5a }

  condition:
    any of them
}