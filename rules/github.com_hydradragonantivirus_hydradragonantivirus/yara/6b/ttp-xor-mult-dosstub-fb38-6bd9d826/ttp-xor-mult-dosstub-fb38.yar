rule TTP_XOR_MULT_DOSStub_fb38 {
  strings:
    $key_fb38 = { af 50 [2] db 48 [2] 9c 4a [2] db 5b [2] 95 57 [2] 99 5d [2] 8e 56 [2] 95 18 [2] a8 }

  condition:
    any of them
}