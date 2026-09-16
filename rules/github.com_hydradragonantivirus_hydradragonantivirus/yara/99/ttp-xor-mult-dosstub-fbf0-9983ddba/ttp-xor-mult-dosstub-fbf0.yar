rule TTP_XOR_MULT_DOSStub_fbf0 {
  strings:
    $key_fbf0 = { af 98 [2] db 80 [2] 9c 82 [2] db 93 [2] 95 9f [2] 99 95 [2] 8e 9e [2] 95 d0 [2] a8 }

  condition:
    any of them
}