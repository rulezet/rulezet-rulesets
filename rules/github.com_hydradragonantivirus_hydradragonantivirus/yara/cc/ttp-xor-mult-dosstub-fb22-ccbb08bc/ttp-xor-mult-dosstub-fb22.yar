rule TTP_XOR_MULT_DOSStub_fb22 {
  strings:
    $key_fb22 = { af 4a [2] db 52 [2] 9c 50 [2] db 41 [2] 95 4d [2] 99 47 [2] 8e 4c [2] 95 02 [2] a8 }

  condition:
    any of them
}