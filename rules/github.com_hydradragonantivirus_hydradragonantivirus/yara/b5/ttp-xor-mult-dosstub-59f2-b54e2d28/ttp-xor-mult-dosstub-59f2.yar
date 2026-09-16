rule TTP_XOR_MULT_DOSStub_59f2 {
  strings:
    $key_59f2 = { 0d 9a [2] 79 82 [2] 3e 80 [2] 79 91 [2] 37 9d [2] 3b 97 [2] 2c 9c [2] 37 d2 [2] 0a }

  condition:
    any of them
}