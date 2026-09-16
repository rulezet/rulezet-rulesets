rule TTP_XOR_MULT_DOSStub_fbe8 {
  strings:
    $key_fbe8 = { af 80 [2] db 98 [2] 9c 9a [2] db 8b [2] 95 87 [2] 99 8d [2] 8e 86 [2] 95 c8 [2] a8 }

  condition:
    any of them
}