rule TTP_XOR_QUAD_CurrentVersionRun_668c {
  strings:
    $key_668c = { 35 e3 [2] 11 ed [2] 3a c1 [2] 14 e3 [2] 00 f8 [2] 0f e2 [2] 11 ff [2] 13 fe [2] 08 f8 [2] 14 ff [2] 08 d0 }

  condition:
    any of them
}