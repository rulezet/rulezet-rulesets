rule TTP_XOR_MULT_DOSStub_4bf2 {
  strings:
    $key_4bf2 = { 1f 9a [2] 6b 82 [2] 2c 80 [2] 6b 91 [2] 25 9d [2] 29 97 [2] 3e 9c [2] 25 d2 [2] 18 }

  condition:
    any of them
}