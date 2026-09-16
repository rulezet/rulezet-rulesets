rule TTP_XOR_QUAD_CurrentVersionRun_0f50 {
  strings:
    $key_0f50 = { 5c 3f [2] 78 31 [2] 53 1d [2] 7d 3f [2] 69 24 [2] 66 3e [2] 78 23 [2] 7a 22 [2] 61 24 [2] 7d 23 [2] 61 0c }

  condition:
    any of them
}