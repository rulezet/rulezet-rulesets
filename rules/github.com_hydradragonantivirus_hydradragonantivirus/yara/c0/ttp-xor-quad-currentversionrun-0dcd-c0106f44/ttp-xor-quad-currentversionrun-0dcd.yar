rule TTP_XOR_QUAD_CurrentVersionRun_0dcd {
  strings:
    $key_0dcd = { 5e a2 [2] 7a ac [2] 51 80 [2] 7f a2 [2] 6b b9 [2] 64 a3 [2] 7a be [2] 78 bf [2] 63 b9 [2] 7f be [2] 63 91 }

  condition:
    any of them
}