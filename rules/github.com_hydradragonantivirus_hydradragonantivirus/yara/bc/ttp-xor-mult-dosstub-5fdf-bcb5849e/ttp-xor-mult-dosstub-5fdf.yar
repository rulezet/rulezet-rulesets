rule TTP_XOR_MULT_DOSStub_5fdf {
  strings:
    $key_5fdf = { 0b b7 [2] 7f af [2] 38 ad [2] 7f bc [2] 31 b0 [2] 3d ba [2] 2a b1 [2] 31 ff [2] 0c }

  condition:
    any of them
}