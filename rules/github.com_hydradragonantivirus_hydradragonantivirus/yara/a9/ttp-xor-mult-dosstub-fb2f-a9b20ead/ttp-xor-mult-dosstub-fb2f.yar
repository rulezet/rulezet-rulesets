rule TTP_XOR_MULT_DOSStub_fb2f {
  strings:
    $key_fb2f = { af 47 [2] db 5f [2] 9c 5d [2] db 4c [2] 95 40 [2] 99 4a [2] 8e 41 [2] 95 0f [2] a8 }

  condition:
    any of them
}