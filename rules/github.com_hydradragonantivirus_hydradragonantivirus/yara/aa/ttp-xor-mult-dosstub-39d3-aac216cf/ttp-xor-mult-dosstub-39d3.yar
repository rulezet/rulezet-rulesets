rule TTP_XOR_MULT_DOSStub_39d3 {
  strings:
    $key_39d3 = { 6d bb [2] 19 a3 [2] 5e a1 [2] 19 b0 [2] 57 bc [2] 5b b6 [2] 4c bd [2] 57 f3 [2] 6a }

  condition:
    any of them
}