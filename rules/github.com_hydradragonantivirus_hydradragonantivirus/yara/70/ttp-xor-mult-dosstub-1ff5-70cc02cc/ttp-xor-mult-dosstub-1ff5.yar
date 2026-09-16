rule TTP_XOR_MULT_DOSStub_1ff5 {
  strings:
    $key_1ff5 = { 4b 9d [2] 3f 85 [2] 78 87 [2] 3f 96 [2] 71 9a [2] 7d 90 [2] 6a 9b [2] 71 d5 [2] 4c }

  condition:
    any of them
}