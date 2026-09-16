rule TTP_XOR_MULT_DOSStub_fb03 {
  strings:
    $key_fb03 = { af 6b [2] db 73 [2] 9c 71 [2] db 60 [2] 95 6c [2] 99 66 [2] 8e 6d [2] 95 23 [2] a8 }

  condition:
    any of them
}