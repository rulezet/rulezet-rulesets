rule TTP_XOR_MULT_DOSStub_ae01 {
  strings:
    $key_ae01 = { fa 69 [2] 8e 71 [2] c9 73 [2] 8e 62 [2] c0 6e [2] cc 64 [2] db 6f [2] c0 21 [2] fd }

  condition:
    any of them
}