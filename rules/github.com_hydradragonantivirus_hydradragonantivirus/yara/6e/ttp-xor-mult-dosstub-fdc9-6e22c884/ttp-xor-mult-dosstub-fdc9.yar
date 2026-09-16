rule TTP_XOR_MULT_DOSStub_fdc9 {
  strings:
    $key_fdc9 = { a9 a1 [2] dd b9 [2] 9a bb [2] dd aa [2] 93 a6 [2] 9f ac [2] 88 a7 [2] 93 e9 [2] ae }

  condition:
    any of them
}