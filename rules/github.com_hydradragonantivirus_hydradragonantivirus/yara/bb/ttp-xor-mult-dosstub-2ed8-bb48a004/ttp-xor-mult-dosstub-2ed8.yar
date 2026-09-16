rule TTP_XOR_MULT_DOSStub_2ed8 {
  strings:
    $key_2ed8 = { 7a b0 [2] 0e a8 [2] 49 aa [2] 0e bb [2] 40 b7 [2] 4c bd [2] 5b b6 [2] 40 f8 [2] 7d }

  condition:
    any of them
}