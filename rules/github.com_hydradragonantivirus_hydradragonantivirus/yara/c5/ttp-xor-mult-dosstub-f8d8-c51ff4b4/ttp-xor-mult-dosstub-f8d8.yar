rule TTP_XOR_MULT_DOSStub_f8d8 {
  strings:
    $key_f8d8 = { ac b0 [2] d8 a8 [2] 9f aa [2] d8 bb [2] 96 b7 [2] 9a bd [2] 8d b6 [2] 96 f8 [2] ab }

  condition:
    any of them
}