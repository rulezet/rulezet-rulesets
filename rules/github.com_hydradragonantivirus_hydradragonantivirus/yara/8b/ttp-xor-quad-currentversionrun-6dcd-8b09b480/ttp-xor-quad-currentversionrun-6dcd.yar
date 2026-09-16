rule TTP_XOR_QUAD_CurrentVersionRun_6dcd {
  strings:
    $key_6dcd = { 3e a2 [2] 1a ac [2] 31 80 [2] 1f a2 [2] 0b b9 [2] 04 a3 [2] 1a be [2] 18 bf [2] 03 b9 [2] 1f be [2] 03 91 }

  condition:
    any of them
}