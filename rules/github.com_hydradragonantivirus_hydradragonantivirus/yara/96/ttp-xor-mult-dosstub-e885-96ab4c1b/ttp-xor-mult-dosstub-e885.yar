rule TTP_XOR_MULT_DOSStub_e885 {
  strings:
    $key_e885 = { bc ed [2] c8 f5 [2] 8f f7 [2] c8 e6 [2] 86 ea [2] 8a e0 [2] 9d eb [2] 86 a5 [2] bb }

  condition:
    any of them
}