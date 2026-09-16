rule TTP_XOR_MULT_DOSStub_1ff8 {
  strings:
    $key_1ff8 = { 4b 90 [2] 3f 88 [2] 78 8a [2] 3f 9b [2] 71 97 [2] 7d 9d [2] 6a 96 [2] 71 d8 [2] 4c }

  condition:
    any of them
}