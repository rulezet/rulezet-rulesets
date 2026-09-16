rule TTP_XOR_MULT_DOSStub_1f90 {
  strings:
    $key_1f90 = { 4b f8 [2] 3f e0 [2] 78 e2 [2] 3f f3 [2] 71 ff [2] 7d f5 [2] 6a fe [2] 71 b0 [2] 4c }

  condition:
    any of them
}