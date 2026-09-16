rule TTP_XOR_MULT_DOSStub_1ef2 {
  strings:
    $key_1ef2 = { 4a 9a [2] 3e 82 [2] 79 80 [2] 3e 91 [2] 70 9d [2] 7c 97 [2] 6b 9c [2] 70 d2 [2] 4d }

  condition:
    any of them
}