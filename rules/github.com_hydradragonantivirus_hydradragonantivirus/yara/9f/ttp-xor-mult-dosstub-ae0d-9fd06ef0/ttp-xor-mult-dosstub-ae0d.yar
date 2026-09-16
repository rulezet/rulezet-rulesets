rule TTP_XOR_MULT_DOSStub_ae0d {
  strings:
    $key_ae0d = { fa 65 [2] 8e 7d [2] c9 7f [2] 8e 6e [2] c0 62 [2] cc 68 [2] db 63 [2] c0 2d [2] fd }

  condition:
    any of them
}