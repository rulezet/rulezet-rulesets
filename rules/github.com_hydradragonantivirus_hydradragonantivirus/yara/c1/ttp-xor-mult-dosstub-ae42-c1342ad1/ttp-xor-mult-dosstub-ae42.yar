rule TTP_XOR_MULT_DOSStub_ae42 {
  strings:
    $key_ae42 = { fa 2a [2] 8e 32 [2] c9 30 [2] 8e 21 [2] c0 2d [2] cc 27 [2] db 2c [2] c0 62 [2] fd }

  condition:
    any of them
}