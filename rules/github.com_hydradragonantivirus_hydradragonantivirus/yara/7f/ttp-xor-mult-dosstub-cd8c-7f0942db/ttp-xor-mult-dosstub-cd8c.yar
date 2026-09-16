rule TTP_XOR_MULT_DOSStub_cd8c {
  strings:
    $key_cd8c = { 99 e4 [2] ed fc [2] aa fe [2] ed ef [2] a3 e3 [2] af e9 [2] b8 e2 [2] a3 ac [2] 9e }

  condition:
    any of them
}