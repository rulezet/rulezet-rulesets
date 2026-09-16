rule TTP_XOR_MULT_DOSStub_6af1 {
  strings:
    $key_6af1 = { 3e 99 [2] 4a 81 [2] 0d 83 [2] 4a 92 [2] 04 9e [2] 08 94 [2] 1f 9f [2] 04 d1 [2] 39 }

  condition:
    any of them
}