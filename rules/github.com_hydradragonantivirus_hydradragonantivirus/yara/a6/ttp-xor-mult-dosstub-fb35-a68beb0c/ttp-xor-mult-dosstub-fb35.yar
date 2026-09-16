rule TTP_XOR_MULT_DOSStub_fb35 {
  strings:
    $key_fb35 = { af 5d [2] db 45 [2] 9c 47 [2] db 56 [2] 95 5a [2] 99 50 [2] 8e 5b [2] 95 15 [2] a8 }

  condition:
    any of them
}