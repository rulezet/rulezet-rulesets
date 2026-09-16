rule TTP_XOR_QUAD_CurrentVersionRun_c3cc {
  strings:
    $key_c3cc = { 90 a3 [2] b4 ad [2] 9f 81 [2] b1 a3 [2] a5 b8 [2] aa a2 [2] b4 bf [2] b6 be [2] ad b8 [2] b1 bf [2] ad 90 }

  condition:
    any of them
}