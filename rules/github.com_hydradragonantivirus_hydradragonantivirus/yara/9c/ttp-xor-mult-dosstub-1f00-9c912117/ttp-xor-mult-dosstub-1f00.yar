rule TTP_XOR_MULT_DOSStub_1f00 {
  strings:
    $key_1f00 = { 4b 68 [2] 3f 70 [2] 78 72 [2] 3f 63 [2] 71 6f [2] 7d 65 [2] 6a 6e [2] 71 20 [2] 4c }

  condition:
    any of them
}