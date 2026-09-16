rule TTP_XOR_MULT_DOSStub_edc7 {
  strings:
    $key_edc7 = { b9 af [2] cd b7 [2] 8a b5 [2] cd a4 [2] 83 a8 [2] 8f a2 [2] 98 a9 [2] 83 e7 [2] be }

  condition:
    any of them
}