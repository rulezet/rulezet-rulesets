rule TTP_XOR_MULT_DOSStub_3fd3 {
  strings:
    $key_3fd3 = { 6b bb [2] 1f a3 [2] 58 a1 [2] 1f b0 [2] 51 bc [2] 5d b6 [2] 4a bd [2] 51 f3 [2] 6c }

  condition:
    any of them
}