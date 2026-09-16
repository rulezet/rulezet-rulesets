rule TTP_XOR_MULT_DOSStub_3fdf {
  strings:
    $key_3fdf = { 6b b7 [2] 1f af [2] 58 ad [2] 1f bc [2] 51 b0 [2] 5d ba [2] 4a b1 [2] 51 ff [2] 6c }

  condition:
    any of them
}