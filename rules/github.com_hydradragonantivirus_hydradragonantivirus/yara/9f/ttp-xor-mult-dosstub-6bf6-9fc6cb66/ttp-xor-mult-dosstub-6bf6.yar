rule TTP_XOR_MULT_DOSStub_6bf6 {
  strings:
    $key_6bf6 = { 3f 9e [2] 4b 86 [2] 0c 84 [2] 4b 95 [2] 05 99 [2] 09 93 [2] 1e 98 [2] 05 d6 [2] 38 }

  condition:
    any of them
}