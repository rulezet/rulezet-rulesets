rule TTP_XOR_QUAD_CurrentVersionRun_0dd1 {
  strings:
    $key_0dd1 = { 5e be [2] 7a b0 [2] 51 9c [2] 7f be [2] 6b a5 [2] 64 bf [2] 7a a2 [2] 78 a3 [2] 63 a5 [2] 7f a2 [2] 63 8d }

  condition:
    any of them
}