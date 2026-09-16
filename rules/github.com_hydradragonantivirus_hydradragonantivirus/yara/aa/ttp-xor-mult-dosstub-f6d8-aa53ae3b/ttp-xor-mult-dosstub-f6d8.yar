rule TTP_XOR_MULT_DOSStub_f6d8 {
  strings:
    $key_f6d8 = { a2 b0 [2] d6 a8 [2] 91 aa [2] d6 bb [2] 98 b7 [2] 94 bd [2] 83 b6 [2] 98 f8 [2] a5 }

  condition:
    any of them
}