rule TTP_XOR_MULT_DOSStub_fad2 {
  strings:
    $key_fad2 = { ae ba [2] da a2 [2] 9d a0 [2] da b1 [2] 94 bd [2] 98 b7 [2] 8f bc [2] 94 f2 [2] a9 }

  condition:
    any of them
}