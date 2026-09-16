rule TTP_XOR_MULT_DOSStub_1f60 {
  strings:
    $key_1f60 = { 4b 08 [2] 3f 10 [2] 78 12 [2] 3f 03 [2] 71 0f [2] 7d 05 [2] 6a 0e [2] 71 40 [2] 4c }

  condition:
    any of them
}