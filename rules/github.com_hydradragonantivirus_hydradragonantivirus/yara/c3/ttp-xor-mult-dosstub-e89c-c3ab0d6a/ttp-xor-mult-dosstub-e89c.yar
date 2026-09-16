rule TTP_XOR_MULT_DOSStub_e89c {
  strings:
    $key_e89c = { bc f4 [2] c8 ec [2] 8f ee [2] c8 ff [2] 86 f3 [2] 8a f9 [2] 9d f2 [2] 86 bc [2] bb }

  condition:
    any of them
}