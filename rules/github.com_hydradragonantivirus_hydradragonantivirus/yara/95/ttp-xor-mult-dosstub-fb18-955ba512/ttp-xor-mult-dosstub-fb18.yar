rule TTP_XOR_MULT_DOSStub_fb18 {
  strings:
    $key_fb18 = { af 70 [2] db 68 [2] 9c 6a [2] db 7b [2] 95 77 [2] 99 7d [2] 8e 76 [2] 95 38 [2] a8 }

  condition:
    any of them
}