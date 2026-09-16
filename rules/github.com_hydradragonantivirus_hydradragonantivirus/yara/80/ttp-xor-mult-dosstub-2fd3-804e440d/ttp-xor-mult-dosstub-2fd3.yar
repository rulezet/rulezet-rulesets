rule TTP_XOR_MULT_DOSStub_2fd3 {
  strings:
    $key_2fd3 = { 7b bb [2] 0f a3 [2] 48 a1 [2] 0f b0 [2] 41 bc [2] 4d b6 [2] 5a bd [2] 41 f3 [2] 7c }

  condition:
    any of them
}