rule TTP_XOR_MULT_DOSStub_7bf2 {
  strings:
    $key_7bf2 = { 2f 9a [2] 5b 82 [2] 1c 80 [2] 5b 91 [2] 15 9d [2] 19 97 [2] 0e 9c [2] 15 d2 [2] 28 }

  condition:
    any of them
}