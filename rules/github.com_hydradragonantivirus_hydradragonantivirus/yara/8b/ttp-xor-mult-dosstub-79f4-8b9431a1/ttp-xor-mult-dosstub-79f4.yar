rule TTP_XOR_MULT_DOSStub_79f4 {
  strings:
    $key_79f4 = { 2d 9c [2] 59 84 [2] 1e 86 [2] 59 97 [2] 17 9b [2] 1b 91 [2] 0c 9a [2] 17 d4 [2] 2a }

  condition:
    any of them
}