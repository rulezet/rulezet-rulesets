rule TTP_XOR_MULT_DOSStub_ae6b {
  strings:
    $key_ae6b = { fa 03 [2] 8e 1b [2] c9 19 [2] 8e 08 [2] c0 04 [2] cc 0e [2] db 05 [2] c0 4b [2] fd }

  condition:
    any of them
}