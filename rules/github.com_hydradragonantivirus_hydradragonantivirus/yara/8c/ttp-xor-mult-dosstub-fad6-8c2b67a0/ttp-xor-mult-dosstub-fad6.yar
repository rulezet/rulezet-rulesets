rule TTP_XOR_MULT_DOSStub_fad6 {
  strings:
    $key_fad6 = { ae be [2] da a6 [2] 9d a4 [2] da b5 [2] 94 b9 [2] 98 b3 [2] 8f b8 [2] 94 f6 [2] a9 }

  condition:
    any of them
}