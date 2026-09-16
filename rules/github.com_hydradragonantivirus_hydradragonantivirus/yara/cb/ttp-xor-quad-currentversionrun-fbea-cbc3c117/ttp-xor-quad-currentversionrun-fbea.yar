rule TTP_XOR_QUAD_CurrentVersionRun_fbea {
  strings:
    $key_fbea = { a8 85 [2] 8c 8b [2] a7 a7 [2] 89 85 [2] 9d 9e [2] 92 84 [2] 8c 99 [2] 8e 98 [2] 95 9e [2] 89 99 [2] 95 b6 }

  condition:
    any of them
}