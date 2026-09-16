rule TTP_XOR_MULT_DOSStub_fb23 {
  strings:
    $key_fb23 = { af 4b [2] db 53 [2] 9c 51 [2] db 40 [2] 95 4c [2] 99 46 [2] 8e 4d [2] 95 03 [2] a8 }

  condition:
    any of them
}