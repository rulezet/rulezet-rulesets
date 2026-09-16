rule TTP_XOR_MULT_DOSStub_5ed8 {
  strings:
    $key_5ed8 = { 0a b0 [2] 7e a8 [2] 39 aa [2] 7e bb [2] 30 b7 [2] 3c bd [2] 2b b6 [2] 30 f8 [2] 0d }

  condition:
    any of them
}