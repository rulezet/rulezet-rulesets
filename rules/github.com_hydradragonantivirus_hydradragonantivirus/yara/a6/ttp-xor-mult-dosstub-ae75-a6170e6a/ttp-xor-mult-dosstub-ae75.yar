rule TTP_XOR_MULT_DOSStub_ae75 {
  strings:
    $key_ae75 = { fa 1d [2] 8e 05 [2] c9 07 [2] 8e 16 [2] c0 1a [2] cc 10 [2] db 1b [2] c0 55 [2] fd }

  condition:
    any of them
}