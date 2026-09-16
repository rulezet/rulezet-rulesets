rule TTP_XOR_MULT_DOSStub_cd9b {
  strings:
    $key_cd9b = { 99 f3 [2] ed eb [2] aa e9 [2] ed f8 [2] a3 f4 [2] af fe [2] b8 f5 [2] a3 bb [2] 9e }

  condition:
    any of them
}