rule TTP_XOR_MULT_DOSStub_6dca {
  strings:
    $key_6dca = { 39 a2 [2] 4d ba [2] 0a b8 [2] 4d a9 [2] 03 a5 [2] 0f af [2] 18 a4 [2] 03 ea [2] 3e }

  condition:
    any of them
}