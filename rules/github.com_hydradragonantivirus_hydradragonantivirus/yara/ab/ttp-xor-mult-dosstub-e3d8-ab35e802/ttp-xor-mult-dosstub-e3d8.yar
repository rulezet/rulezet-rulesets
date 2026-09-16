rule TTP_XOR_MULT_DOSStub_e3d8 {
  strings:
    $key_e3d8 = { b7 b0 [2] c3 a8 [2] 84 aa [2] c3 bb [2] 8d b7 [2] 81 bd [2] 96 b6 [2] 8d f8 [2] b0 }

  condition:
    any of them
}