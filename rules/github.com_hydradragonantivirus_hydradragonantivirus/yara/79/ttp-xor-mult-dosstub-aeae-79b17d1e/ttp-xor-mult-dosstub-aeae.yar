rule TTP_XOR_MULT_DOSStub_aeae {
  strings:
    $key_aeae = { fa c6 [2] 8e de [2] c9 dc [2] 8e cd [2] c0 c1 [2] cc cb [2] db c0 [2] c0 8e [2] fd }

  condition:
    any of them
}