rule TTP_XOR_MULT_DOSStub_af90 {
  strings:
    $key_af90 = { fb f8 [2] 8f e0 [2] c8 e2 [2] 8f f3 [2] c1 ff [2] cd f5 [2] da fe [2] c1 b0 [2] fc }

  condition:
    any of them
}