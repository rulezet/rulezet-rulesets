rule TTP_XOR_MULT_DOSStub_6bf1 {
  strings:
    $key_6bf1 = { 3f 99 [2] 4b 81 [2] 0c 83 [2] 4b 92 [2] 05 9e [2] 09 94 [2] 1e 9f [2] 05 d1 [2] 38 }

  condition:
    any of them
}