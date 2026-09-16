rule TTP_XOR_MULT_DOSStub_fbf5 {
  strings:
    $key_fbf5 = { af 9d [2] db 85 [2] 9c 87 [2] db 96 [2] 95 9a [2] 99 90 [2] 8e 9b [2] 95 d5 [2] a8 }

  condition:
    any of them
}