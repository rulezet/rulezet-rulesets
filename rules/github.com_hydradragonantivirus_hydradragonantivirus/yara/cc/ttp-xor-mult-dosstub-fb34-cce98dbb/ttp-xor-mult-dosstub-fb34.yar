rule TTP_XOR_MULT_DOSStub_fb34 {
  strings:
    $key_fb34 = { af 5c [2] db 44 [2] 9c 46 [2] db 57 [2] 95 5b [2] 99 51 [2] 8e 5a [2] 95 14 [2] a8 }

  condition:
    any of them
}