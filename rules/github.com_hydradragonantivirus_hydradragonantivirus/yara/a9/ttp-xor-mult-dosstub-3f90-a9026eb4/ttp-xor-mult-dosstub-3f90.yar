rule TTP_XOR_MULT_DOSStub_3f90 {
  strings:
    $key_3f90 = { 6b f8 [2] 1f e0 [2] 58 e2 [2] 1f f3 [2] 51 ff [2] 5d f5 [2] 4a fe [2] 51 b0 [2] 6c }

  condition:
    any of them
}