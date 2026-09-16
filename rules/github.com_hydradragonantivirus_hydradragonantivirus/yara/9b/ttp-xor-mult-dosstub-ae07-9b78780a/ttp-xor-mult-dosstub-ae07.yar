rule TTP_XOR_MULT_DOSStub_ae07 {
  strings:
    $key_ae07 = { fa 6f [2] 8e 77 [2] c9 75 [2] 8e 64 [2] c0 68 [2] cc 62 [2] db 69 [2] c0 27 [2] fd }

  condition:
    any of them
}