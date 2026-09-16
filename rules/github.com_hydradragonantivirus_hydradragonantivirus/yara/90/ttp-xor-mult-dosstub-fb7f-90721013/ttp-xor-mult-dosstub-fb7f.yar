rule TTP_XOR_MULT_DOSStub_fb7f {
  strings:
    $key_fb7f = { af 17 [2] db 0f [2] 9c 0d [2] db 1c [2] 95 10 [2] 99 1a [2] 8e 11 [2] 95 5f [2] a8 }

  condition:
    any of them
}