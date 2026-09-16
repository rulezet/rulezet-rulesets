rule TTP_XOR_MULT_DOSStub_5fd3 {
  strings:
    $key_5fd3 = { 0b bb [2] 7f a3 [2] 38 a1 [2] 7f b0 [2] 31 bc [2] 3d b6 [2] 2a bd [2] 31 f3 [2] 0c }

  condition:
    any of them
}