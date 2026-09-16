rule TTP_XOR_MULT_DOSStub_0fd8 {
  strings:
    $key_0fd8 = { 5b b0 [2] 2f a8 [2] 68 aa [2] 2f bb [2] 61 b7 [2] 6d bd [2] 7a b6 [2] 61 f8 [2] 5c }

  condition:
    any of them
}