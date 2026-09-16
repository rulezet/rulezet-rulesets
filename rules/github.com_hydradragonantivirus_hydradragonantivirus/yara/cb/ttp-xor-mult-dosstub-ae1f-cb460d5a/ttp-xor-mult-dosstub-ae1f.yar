rule TTP_XOR_MULT_DOSStub_ae1f {
  strings:
    $key_ae1f = { fa 77 [2] 8e 6f [2] c9 6d [2] 8e 7c [2] c0 70 [2] cc 7a [2] db 71 [2] c0 3f [2] fd }

  condition:
    any of them
}