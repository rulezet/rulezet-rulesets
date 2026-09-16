rule TTP_XOR_MULT_DOSStub_1ff0 {
  strings:
    $key_1ff0 = { 4b 98 [2] 3f 80 [2] 78 82 [2] 3f 93 [2] 71 9f [2] 7d 95 [2] 6a 9e [2] 71 d0 [2] 4c }

  condition:
    any of them
}