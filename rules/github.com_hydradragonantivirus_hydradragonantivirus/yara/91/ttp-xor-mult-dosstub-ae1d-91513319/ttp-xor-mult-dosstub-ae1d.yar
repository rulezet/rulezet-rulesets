rule TTP_XOR_MULT_DOSStub_ae1d {
  strings:
    $key_ae1d = { fa 75 [2] 8e 6d [2] c9 6f [2] 8e 7e [2] c0 72 [2] cc 78 [2] db 73 [2] c0 3d [2] fd }

  condition:
    any of them
}