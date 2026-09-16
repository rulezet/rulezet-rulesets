rule TTP_XOR_MULT_DOSStub_fb19 {
  strings:
    $key_fb19 = { af 71 [2] db 69 [2] 9c 6b [2] db 7a [2] 95 76 [2] 99 7c [2] 8e 77 [2] 95 39 [2] a8 }

  condition:
    any of them
}