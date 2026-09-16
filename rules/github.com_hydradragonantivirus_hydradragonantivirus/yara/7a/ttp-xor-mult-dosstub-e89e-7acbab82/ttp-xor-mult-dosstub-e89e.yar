rule TTP_XOR_MULT_DOSStub_e89e {
  strings:
    $key_e89e = { bc f6 [2] c8 ee [2] 8f ec [2] c8 fd [2] 86 f1 [2] 8a fb [2] 9d f0 [2] 86 be [2] bb }

  condition:
    any of them
}