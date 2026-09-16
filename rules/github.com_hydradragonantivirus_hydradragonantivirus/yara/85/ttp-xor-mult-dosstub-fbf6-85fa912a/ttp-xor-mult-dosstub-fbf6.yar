rule TTP_XOR_MULT_DOSStub_fbf6 {
  strings:
    $key_fbf6 = { af 9e [2] db 86 [2] 9c 84 [2] db 95 [2] 95 99 [2] 99 93 [2] 8e 98 [2] 95 d6 [2] a8 }

  condition:
    any of them
}