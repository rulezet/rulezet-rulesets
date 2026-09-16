rule TTP_XOR_MULT_DOSStub_aef5 {
  strings:
    $key_aef5 = { fa 9d [2] 8e 85 [2] c9 87 [2] 8e 96 [2] c0 9a [2] cc 90 [2] db 9b [2] c0 d5 [2] fd }

  condition:
    any of them
}