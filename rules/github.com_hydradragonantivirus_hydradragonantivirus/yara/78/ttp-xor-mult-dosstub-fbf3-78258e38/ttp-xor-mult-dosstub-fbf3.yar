rule TTP_XOR_MULT_DOSStub_fbf3 {
  strings:
    $key_fbf3 = { af 9b [2] db 83 [2] 9c 81 [2] db 90 [2] 95 9c [2] 99 96 [2] 8e 9d [2] 95 d3 [2] a8 }

  condition:
    any of them
}