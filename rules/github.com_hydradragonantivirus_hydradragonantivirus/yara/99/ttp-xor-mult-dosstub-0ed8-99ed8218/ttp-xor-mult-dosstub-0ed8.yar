rule TTP_XOR_MULT_DOSStub_0ed8 {
  strings:
    $key_0ed8 = { 5a b0 [2] 2e a8 [2] 69 aa [2] 2e bb [2] 60 b7 [2] 6c bd [2] 7b b6 [2] 60 f8 [2] 5d }

  condition:
    any of them
}