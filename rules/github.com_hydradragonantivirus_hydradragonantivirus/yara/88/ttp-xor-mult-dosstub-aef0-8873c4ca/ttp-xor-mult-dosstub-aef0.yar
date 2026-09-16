rule TTP_XOR_MULT_DOSStub_aef0 {
  strings:
    $key_aef0 = { fa 98 [2] 8e 80 [2] c9 82 [2] 8e 93 [2] c0 9f [2] cc 95 [2] db 9e [2] c0 d0 [2] fd }

  condition:
    any of them
}