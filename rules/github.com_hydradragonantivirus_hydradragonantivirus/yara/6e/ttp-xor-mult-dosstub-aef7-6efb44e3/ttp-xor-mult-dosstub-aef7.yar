rule TTP_XOR_MULT_DOSStub_aef7 {
  strings:
    $key_aef7 = { fa 9f [2] 8e 87 [2] c9 85 [2] 8e 94 [2] c0 98 [2] cc 92 [2] db 99 [2] c0 d7 [2] fd }

  condition:
    any of them
}