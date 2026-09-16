rule TTP_XOR_MULT_DOSStub_fbe1 {
  strings:
    $key_fbe1 = { af 89 [2] db 91 [2] 9c 93 [2] db 82 [2] 95 8e [2] 99 84 [2] 8e 8f [2] 95 c1 [2] a8 }

  condition:
    any of them
}