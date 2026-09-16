rule TTP_XOR_MULT_DOSStub_fbe3 {
  strings:
    $key_fbe3 = { af 8b [2] db 93 [2] 9c 91 [2] db 80 [2] 95 8c [2] 99 86 [2] 8e 8d [2] 95 c3 [2] a8 }

  condition:
    any of them
}