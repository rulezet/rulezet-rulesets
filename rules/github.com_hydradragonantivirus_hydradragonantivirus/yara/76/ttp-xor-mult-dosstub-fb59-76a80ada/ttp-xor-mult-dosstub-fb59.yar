rule TTP_XOR_MULT_DOSStub_fb59 {
  strings:
    $key_fb59 = { af 31 [2] db 29 [2] 9c 2b [2] db 3a [2] 95 36 [2] 99 3c [2] 8e 37 [2] 95 79 [2] a8 }

  condition:
    any of them
}