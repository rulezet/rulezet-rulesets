rule TTP_XOR_QUAD_CurrentVersionRun_3dd1 {
  strings:
    $key_3dd1 = { 6e be [2] 4a b0 [2] 61 9c [2] 4f be [2] 5b a5 [2] 54 bf [2] 4a a2 [2] 48 a3 [2] 53 a5 [2] 4f a2 [2] 53 8d }

  condition:
    any of them
}