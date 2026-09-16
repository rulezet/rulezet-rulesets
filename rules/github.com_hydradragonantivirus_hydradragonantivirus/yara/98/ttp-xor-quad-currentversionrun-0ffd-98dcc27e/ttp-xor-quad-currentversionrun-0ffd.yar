rule TTP_XOR_QUAD_CurrentVersionRun_0ffd {
  strings:
    $key_0ffd = { 5c 92 [2] 78 9c [2] 53 b0 [2] 7d 92 [2] 69 89 [2] 66 93 [2] 78 8e [2] 7a 8f [2] 61 89 [2] 7d 8e [2] 61 a1 }

  condition:
    any of them
}