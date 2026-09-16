rule TTP_XOR_MULT_DOSStub_5f90 {
  strings:
    $key_5f90 = { 0b f8 [2] 7f e0 [2] 38 e2 [2] 7f f3 [2] 31 ff [2] 3d f5 [2] 2a fe [2] 31 b0 [2] 0c }

  condition:
    any of them
}