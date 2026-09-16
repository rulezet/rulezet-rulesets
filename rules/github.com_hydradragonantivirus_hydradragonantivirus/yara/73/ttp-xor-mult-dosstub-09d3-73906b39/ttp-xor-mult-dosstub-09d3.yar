rule TTP_XOR_MULT_DOSStub_09d3 {
  strings:
    $key_09d3 = { 5d bb [2] 29 a3 [2] 6e a1 [2] 29 b0 [2] 67 bc [2] 6b b6 [2] 7c bd [2] 67 f3 [2] 5a }

  condition:
    any of them
}