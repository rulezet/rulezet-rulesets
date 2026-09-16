rule TTP_XOR_MULT_DOSStub_1ff4 {
  strings:
    $key_1ff4 = { 4b 9c [2] 3f 84 [2] 78 86 [2] 3f 97 [2] 71 9b [2] 7d 91 [2] 6a 9a [2] 71 d4 [2] 4c }

  condition:
    any of them
}