rule TTP_XOR_MULT_DOSStub_aee4 {
  strings:
    $key_aee4 = { fa 8c [2] 8e 94 [2] c9 96 [2] 8e 87 [2] c0 8b [2] cc 81 [2] db 8a [2] c0 c4 [2] fd }

  condition:
    any of them
}