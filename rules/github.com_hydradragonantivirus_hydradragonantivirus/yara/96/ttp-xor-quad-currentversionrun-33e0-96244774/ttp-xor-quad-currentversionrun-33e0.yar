rule TTP_XOR_QUAD_CurrentVersionRun_33e0 {
  strings:
    $key_33e0 = { 60 8f [2] 44 81 [2] 6f ad [2] 41 8f [2] 55 94 [2] 5a 8e [2] 44 93 [2] 46 92 [2] 5d 94 [2] 41 93 [2] 5d bc }

  condition:
    any of them
}