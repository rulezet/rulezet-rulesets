rule TTP_XOR_MULT_DOSStub_ae67 {
  strings:
    $key_ae67 = { fa 0f [2] 8e 17 [2] c9 15 [2] 8e 04 [2] c0 08 [2] cc 02 [2] db 09 [2] c0 47 [2] fd }

  condition:
    any of them
}