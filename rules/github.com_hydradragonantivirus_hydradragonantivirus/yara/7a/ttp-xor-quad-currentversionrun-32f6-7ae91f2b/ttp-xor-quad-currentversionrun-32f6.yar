rule TTP_XOR_QUAD_CurrentVersionRun_32f6 {
  strings:
    $key_32f6 = { 61 99 [2] 45 97 [2] 6e bb [2] 40 99 [2] 54 82 [2] 5b 98 [2] 45 85 [2] 47 84 [2] 5c 82 [2] 40 85 [2] 5c aa }

  condition:
    any of them
}