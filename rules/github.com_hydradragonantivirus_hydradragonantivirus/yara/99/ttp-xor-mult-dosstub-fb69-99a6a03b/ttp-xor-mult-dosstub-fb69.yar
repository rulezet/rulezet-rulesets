rule TTP_XOR_MULT_DOSStub_fb69 {
  strings:
    $key_fb69 = { af 01 [2] db 19 [2] 9c 1b [2] db 0a [2] 95 06 [2] 99 0c [2] 8e 07 [2] 95 49 [2] a8 }

  condition:
    any of them
}