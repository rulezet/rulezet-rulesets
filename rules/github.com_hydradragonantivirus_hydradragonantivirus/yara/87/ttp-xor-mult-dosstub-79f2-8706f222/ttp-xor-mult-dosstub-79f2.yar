rule TTP_XOR_MULT_DOSStub_79f2 {
  strings:
    $key_79f2 = { 2d 9a [2] 59 82 [2] 1e 80 [2] 59 91 [2] 17 9d [2] 1b 97 [2] 0c 9c [2] 17 d2 [2] 2a }

  condition:
    any of them
}