rule TTP_XOR_MULT_DOSStub_e88b {
  strings:
    $key_e88b = { bc e3 [2] c8 fb [2] 8f f9 [2] c8 e8 [2] 86 e4 [2] 8a ee [2] 9d e5 [2] 86 ab [2] bb }

  condition:
    any of them
}