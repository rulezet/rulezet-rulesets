rule TTP_XOR_MULT_DOSStub_ae37 {
  strings:
    $key_ae37 = { fa 5f [2] 8e 47 [2] c9 45 [2] 8e 54 [2] c0 58 [2] cc 52 [2] db 59 [2] c0 17 [2] fd }

  condition:
    any of them
}