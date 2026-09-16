rule TTP_XOR_MULT_DOSStub_4ef2 {
  strings:
    $key_4ef2 = { 1a 9a [2] 6e 82 [2] 29 80 [2] 6e 91 [2] 20 9d [2] 2c 97 [2] 3b 9c [2] 20 d2 [2] 1d }

  condition:
    any of them
}