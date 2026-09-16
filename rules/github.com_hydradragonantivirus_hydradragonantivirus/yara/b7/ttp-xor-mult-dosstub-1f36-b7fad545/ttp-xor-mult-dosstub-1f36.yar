rule TTP_XOR_MULT_DOSStub_1f36 {
  strings:
    $key_1f36 = { 4b 5e [2] 3f 46 [2] 78 44 [2] 3f 55 [2] 71 59 [2] 7d 53 [2] 6a 58 [2] 71 16 [2] 4c }

  condition:
    any of them
}