rule TTP_XOR_MULT_DOSStub_fbe9 {
  strings:
    $key_fbe9 = { af 81 [2] db 99 [2] 9c 9b [2] db 8a [2] 95 86 [2] 99 8c [2] 8e 87 [2] 95 c9 [2] a8 }

  condition:
    any of them
}