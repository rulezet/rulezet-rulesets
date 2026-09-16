rule TTP_XOR_MULT_DOSStub_fb5a {
  strings:
    $key_fb5a = { af 32 [2] db 2a [2] 9c 28 [2] db 39 [2] 95 35 [2] 99 3f [2] 8e 34 [2] 95 7a [2] a8 }

  condition:
    any of them
}