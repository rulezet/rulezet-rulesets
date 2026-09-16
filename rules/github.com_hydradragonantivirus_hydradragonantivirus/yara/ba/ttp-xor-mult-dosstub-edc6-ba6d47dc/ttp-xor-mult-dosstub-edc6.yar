rule TTP_XOR_MULT_DOSStub_edc6 {
  strings:
    $key_edc6 = { b9 ae [2] cd b6 [2] 8a b4 [2] cd a5 [2] 83 a9 [2] 8f a3 [2] 98 a8 [2] 83 e6 [2] be }

  condition:
    any of them
}