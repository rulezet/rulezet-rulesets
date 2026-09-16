rule TTP_XOR_MULT_DOSStub_aeef {
  strings:
    $key_aeef = { fa 87 [2] 8e 9f [2] c9 9d [2] 8e 8c [2] c0 80 [2] cc 8a [2] db 81 [2] c0 cf [2] fd }

  condition:
    any of them
}