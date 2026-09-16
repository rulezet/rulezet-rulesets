rule TTP_XOR_MULT_DOSStub_1fe0 {
  strings:
    $key_1fe0 = { 4b 88 [2] 3f 90 [2] 78 92 [2] 3f 83 [2] 71 8f [2] 7d 85 [2] 6a 8e [2] 71 c0 [2] 4c }

  condition:
    any of them
}