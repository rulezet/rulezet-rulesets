rule TTP_XOR_MULT_DOSStub_0ad8 {
  strings:
    $key_0ad8 = { 5e b0 [2] 2a a8 [2] 6d aa [2] 2a bb [2] 64 b7 [2] 68 bd [2] 7f b6 [2] 64 f8 [2] 59 }

  condition:
    any of them
}