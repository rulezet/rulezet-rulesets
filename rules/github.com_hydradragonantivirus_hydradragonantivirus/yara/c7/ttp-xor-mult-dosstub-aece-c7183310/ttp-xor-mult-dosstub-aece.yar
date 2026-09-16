rule TTP_XOR_MULT_DOSStub_aece {
  strings:
    $key_aece = { fa a6 [2] 8e be [2] c9 bc [2] 8e ad [2] c0 a1 [2] cc ab [2] db a0 [2] c0 ee [2] fd }

  condition:
    any of them
}