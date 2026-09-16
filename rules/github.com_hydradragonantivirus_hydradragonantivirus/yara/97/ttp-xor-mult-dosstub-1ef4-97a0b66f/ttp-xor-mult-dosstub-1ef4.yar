rule TTP_XOR_MULT_DOSStub_1ef4 {
  strings:
    $key_1ef4 = { 4a 9c [2] 3e 84 [2] 79 86 [2] 3e 97 [2] 70 9b [2] 7c 91 [2] 6b 9a [2] 70 d4 [2] 4d }

  condition:
    any of them
}