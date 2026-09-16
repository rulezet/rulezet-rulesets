rule TTP_XOR_MULT_DOSStub_fb73 {
  strings:
    $key_fb73 = { af 1b [2] db 03 [2] 9c 01 [2] db 10 [2] 95 1c [2] 99 16 [2] 8e 1d [2] 95 53 [2] a8 }

  condition:
    any of them
}