rule TTP_XOR_MULT_DOSStub_1bf2 {
  strings:
    $key_1bf2 = { 4f 9a [2] 3b 82 [2] 7c 80 [2] 3b 91 [2] 75 9d [2] 79 97 [2] 6e 9c [2] 75 d2 [2] 48 }

  condition:
    any of them
}