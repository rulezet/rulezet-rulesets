rule TTP_XOR_QUAD_CurrentVersionRun_3bf1 {
  strings:
    $key_3bf1 = { 68 9e [2] 4c 90 [2] 67 bc [2] 49 9e [2] 5d 85 [2] 52 9f [2] 4c 82 [2] 4e 83 [2] 55 85 [2] 49 82 [2] 55 ad }

  condition:
    any of them
}