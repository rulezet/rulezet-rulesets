rule TTP_XOR_MULT_DOSStub_fb13 {
  strings:
    $key_fb13 = { af 7b [2] db 63 [2] 9c 61 [2] db 70 [2] 95 7c [2] 99 76 [2] 8e 7d [2] 95 33 [2] a8 }

  condition:
    any of them
}