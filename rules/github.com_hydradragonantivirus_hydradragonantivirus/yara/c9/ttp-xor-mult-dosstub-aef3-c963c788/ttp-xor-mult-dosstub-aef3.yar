rule TTP_XOR_MULT_DOSStub_aef3 {
  strings:
    $key_aef3 = { fa 9b [2] 8e 83 [2] c9 81 [2] 8e 90 [2] c0 9c [2] cc 96 [2] db 9d [2] c0 d3 [2] fd }

  condition:
    any of them
}