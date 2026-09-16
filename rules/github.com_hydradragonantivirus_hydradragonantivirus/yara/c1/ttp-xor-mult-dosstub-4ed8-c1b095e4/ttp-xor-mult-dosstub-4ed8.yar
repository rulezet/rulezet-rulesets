rule TTP_XOR_MULT_DOSStub_4ed8 {
  strings:
    $key_4ed8 = { 1a b0 [2] 6e a8 [2] 29 aa [2] 6e bb [2] 20 b7 [2] 2c bd [2] 3b b6 [2] 20 f8 [2] 1d }

  condition:
    any of them
}