rule TTP_XOR_QUAD_CurrentVersionRun_d2cc {
  strings:
    $key_d2cc = { 81 a3 [2] a5 ad [2] 8e 81 [2] a0 a3 [2] b4 b8 [2] bb a2 [2] a5 bf [2] a7 be [2] bc b8 [2] a0 bf [2] bc 90 }

  condition:
    any of them
}