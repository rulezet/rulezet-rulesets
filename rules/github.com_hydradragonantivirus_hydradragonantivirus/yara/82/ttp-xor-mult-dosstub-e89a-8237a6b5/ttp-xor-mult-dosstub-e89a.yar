rule TTP_XOR_MULT_DOSStub_e89a {
  strings:
    $key_e89a = { bc f2 [2] c8 ea [2] 8f e8 [2] c8 f9 [2] 86 f5 [2] 8a ff [2] 9d f4 [2] 86 ba [2] bb }

  condition:
    any of them
}