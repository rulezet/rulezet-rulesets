rule TTP_XOR_MULT_DOSStub_5bf2 {
  strings:
    $key_5bf2 = { 0f 9a [2] 7b 82 [2] 3c 80 [2] 7b 91 [2] 35 9d [2] 39 97 [2] 2e 9c [2] 35 d2 [2] 08 }

  condition:
    any of them
}