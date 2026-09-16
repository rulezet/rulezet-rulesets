rule TTP_XOR_MULT_DOSStub_fbf1 {
  strings:
    $key_fbf1 = { af 99 [2] db 81 [2] 9c 83 [2] db 92 [2] 95 9e [2] 99 94 [2] 8e 9f [2] 95 d1 [2] a8 }

  condition:
    any of them
}