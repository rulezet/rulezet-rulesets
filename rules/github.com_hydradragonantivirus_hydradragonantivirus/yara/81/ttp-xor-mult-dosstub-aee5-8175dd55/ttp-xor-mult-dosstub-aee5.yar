rule TTP_XOR_MULT_DOSStub_aee5 {
  strings:
    $key_aee5 = { fa 8d [2] 8e 95 [2] c9 97 [2] 8e 86 [2] c0 8a [2] cc 80 [2] db 8b [2] c0 c5 [2] fd }

  condition:
    any of them
}