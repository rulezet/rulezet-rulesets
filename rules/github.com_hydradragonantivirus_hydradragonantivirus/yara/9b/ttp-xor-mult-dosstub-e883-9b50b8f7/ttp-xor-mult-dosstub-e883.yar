rule TTP_XOR_MULT_DOSStub_e883 {
  strings:
    $key_e883 = { bc eb [2] c8 f3 [2] 8f f1 [2] c8 e0 [2] 86 ec [2] 8a e6 [2] 9d ed [2] 86 a3 [2] bb }

  condition:
    any of them
}