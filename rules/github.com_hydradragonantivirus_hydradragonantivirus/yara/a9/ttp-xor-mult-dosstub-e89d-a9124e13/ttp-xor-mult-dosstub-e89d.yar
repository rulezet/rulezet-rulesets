rule TTP_XOR_MULT_DOSStub_e89d {
  strings:
    $key_e89d = { bc f5 [2] c8 ed [2] 8f ef [2] c8 fe [2] 86 f2 [2] 8a f8 [2] 9d f3 [2] 86 bd [2] bb }

  condition:
    any of them
}