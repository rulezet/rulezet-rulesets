rule TTP_XOR_MULT_DOSStub_4ff2 {
  strings:
    $key_4ff2 = { 1b 9a [2] 6f 82 [2] 28 80 [2] 6f 91 [2] 21 9d [2] 2d 97 [2] 3a 9c [2] 21 d2 [2] 1c }

  condition:
    any of them
}