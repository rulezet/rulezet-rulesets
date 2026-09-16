rule TTP_XOR_MULT_DOSStub_19d3 {
  strings:
    $key_19d3 = { 4d bb [2] 39 a3 [2] 7e a1 [2] 39 b0 [2] 77 bc [2] 7b b6 [2] 6c bd [2] 77 f3 [2] 4a }

  condition:
    any of them
}