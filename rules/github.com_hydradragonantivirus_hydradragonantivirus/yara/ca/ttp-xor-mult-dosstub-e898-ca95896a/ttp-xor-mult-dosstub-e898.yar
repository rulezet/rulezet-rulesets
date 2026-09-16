rule TTP_XOR_MULT_DOSStub_e898 {
  strings:
    $key_e898 = { bc f0 [2] c8 e8 [2] 8f ea [2] c8 fb [2] 86 f7 [2] 8a fd [2] 9d f6 [2] 86 b8 [2] bb }

  condition:
    any of them
}