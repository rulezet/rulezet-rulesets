rule TTP_XOR_MULT_DOSStub_fb4a {
  strings:
    $key_fb4a = { af 22 [2] db 3a [2] 9c 38 [2] db 29 [2] 95 25 [2] 99 2f [2] 8e 24 [2] 95 6a [2] a8 }

  condition:
    any of them
}