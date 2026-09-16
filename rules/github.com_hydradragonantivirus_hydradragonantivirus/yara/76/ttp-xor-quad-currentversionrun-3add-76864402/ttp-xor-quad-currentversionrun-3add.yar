rule TTP_XOR_QUAD_CurrentVersionRun_3add {
  strings:
    $key_3add = { 69 b2 [2] 4d bc [2] 66 90 [2] 48 b2 [2] 5c a9 [2] 53 b3 [2] 4d ae [2] 4f af [2] 54 a9 [2] 48 ae [2] 54 81 }

  condition:
    any of them
}