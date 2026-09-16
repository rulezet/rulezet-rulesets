rule TTP_XOR_MULT_DOSStub_e9d8 {
  strings:
    $key_e9d8 = { bd b0 [2] c9 a8 [2] 8e aa [2] c9 bb [2] 87 b7 [2] 8b bd [2] 9c b6 [2] 87 f8 [2] ba }

  condition:
    any of them
}