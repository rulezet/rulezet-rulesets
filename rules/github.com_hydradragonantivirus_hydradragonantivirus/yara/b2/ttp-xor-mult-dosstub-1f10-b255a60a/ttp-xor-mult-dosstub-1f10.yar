rule TTP_XOR_MULT_DOSStub_1f10 {
  strings:
    $key_1f10 = { 4b 78 [2] 3f 60 [2] 78 62 [2] 3f 73 [2] 71 7f [2] 7d 75 [2] 6a 7e [2] 71 30 [2] 4c }

  condition:
    any of them
}