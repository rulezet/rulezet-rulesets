rule TTP_XOR_MULT_DOSStub_fbe5 {
  strings:
    $key_fbe5 = { af 8d [2] db 95 [2] 9c 97 [2] db 86 [2] 95 8a [2] 99 80 [2] 8e 8b [2] 95 c5 [2] a8 }

  condition:
    any of them
}