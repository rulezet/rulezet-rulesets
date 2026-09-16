rule TTP_XOR_MULT_DOSStub_fbe2 {
  strings:
    $key_fbe2 = { af 8a [2] db 92 [2] 9c 90 [2] db 81 [2] 95 8d [2] 99 87 [2] 8e 8c [2] 95 c2 [2] a8 }

  condition:
    any of them
}