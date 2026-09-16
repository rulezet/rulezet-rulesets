rule TTP_XOR_MULT_DOSStub_ae76 {
  strings:
    $key_ae76 = { fa 1e [2] 8e 06 [2] c9 04 [2] 8e 15 [2] c0 19 [2] cc 13 [2] db 18 [2] c0 56 [2] fd }

  condition:
    any of them
}