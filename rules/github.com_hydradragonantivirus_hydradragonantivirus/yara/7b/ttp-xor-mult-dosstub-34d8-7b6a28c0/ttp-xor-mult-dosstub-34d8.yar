rule TTP_XOR_MULT_DOSStub_34d8 {
  strings:
    $key_34d8 = { 60 b0 [2] 14 a8 [2] 53 aa [2] 14 bb [2] 5a b7 [2] 56 bd [2] 41 b6 [2] 5a f8 [2] 67 }

  condition:
    any of them
}