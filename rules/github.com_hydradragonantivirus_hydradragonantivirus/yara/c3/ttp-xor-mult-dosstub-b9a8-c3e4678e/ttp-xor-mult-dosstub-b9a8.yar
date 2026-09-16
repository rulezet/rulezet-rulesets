rule TTP_XOR_MULT_DOSStub_b9a8 {
  strings:
    $key_b9a8 = { ed c0 [2] 99 d8 [2] de da [2] 99 cb [2] d7 c7 [2] db cd [2] cc c6 [2] d7 88 [2] ea }

  condition:
    any of them
}