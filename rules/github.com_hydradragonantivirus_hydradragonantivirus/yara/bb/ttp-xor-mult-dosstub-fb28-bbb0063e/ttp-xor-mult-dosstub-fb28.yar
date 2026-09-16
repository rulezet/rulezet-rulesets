rule TTP_XOR_MULT_DOSStub_fb28 {
  strings:
    $key_fb28 = { af 40 [2] db 58 [2] 9c 5a [2] db 4b [2] 95 47 [2] 99 4d [2] 8e 46 [2] 95 08 [2] a8 }

  condition:
    any of them
}