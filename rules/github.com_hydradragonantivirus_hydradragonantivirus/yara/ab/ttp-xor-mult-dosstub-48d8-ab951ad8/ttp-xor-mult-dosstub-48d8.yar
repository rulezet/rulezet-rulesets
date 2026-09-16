rule TTP_XOR_MULT_DOSStub_48d8 {
  strings:
    $key_48d8 = { 1c b0 [2] 68 a8 [2] 2f aa [2] 68 bb [2] 26 b7 [2] 2a bd [2] 3d b6 [2] 26 f8 [2] 1b }

  condition:
    any of them
}