rule TTP_XOR_MULT_DOSStub_7df2 {
  strings:
    $key_7df2 = { 29 9a [2] 5d 82 [2] 1a 80 [2] 5d 91 [2] 13 9d [2] 1f 97 [2] 08 9c [2] 13 d2 [2] 2e }

  condition:
    any of them
}