rule TTP_XOR_MULT_DOSStub_2989 {
  strings:
    $key_2989 = { 7d e1 [2] 09 f9 [2] 4e fb [2] 09 ea [2] 47 e6 [2] 4b ec [2] 5c e7 [2] 47 a9 [2] 7a }

  condition:
    any of them
}