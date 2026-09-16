rule TTP_XOR_MULT_DOSStub_fb53 {
  strings:
    $key_fb53 = { af 3b [2] db 23 [2] 9c 21 [2] db 30 [2] 95 3c [2] 99 36 [2] 8e 3d [2] 95 73 [2] a8 }

  condition:
    any of them
}