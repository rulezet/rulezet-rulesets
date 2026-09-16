rule TTP_XOR_MULT_DOSStub_1f21 {
  strings:
    $key_1f21 = { 4b 49 [2] 3f 51 [2] 78 53 [2] 3f 42 [2] 71 4e [2] 7d 44 [2] 6a 4f [2] 71 01 [2] 4c }

  condition:
    any of them
}