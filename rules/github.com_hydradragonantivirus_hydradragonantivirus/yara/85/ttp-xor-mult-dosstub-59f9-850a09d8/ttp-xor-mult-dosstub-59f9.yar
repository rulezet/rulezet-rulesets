rule TTP_XOR_MULT_DOSStub_59f9 {
  strings:
    $key_59f9 = { 0d 91 [2] 79 89 [2] 3e 8b [2] 79 9a [2] 37 96 [2] 3b 9c [2] 2c 97 [2] 37 d9 [2] 0a }

  condition:
    any of them
}