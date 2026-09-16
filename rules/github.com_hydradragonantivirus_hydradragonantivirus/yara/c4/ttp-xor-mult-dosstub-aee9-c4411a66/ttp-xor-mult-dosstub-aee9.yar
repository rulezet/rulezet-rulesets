rule TTP_XOR_MULT_DOSStub_aee9 {
  strings:
    $key_aee9 = { fa 81 [2] 8e 99 [2] c9 9b [2] 8e 8a [2] c0 86 [2] cc 8c [2] db 87 [2] c0 c9 [2] fd }

  condition:
    any of them
}