rule TTP_XOR_QUAD_CurrentVersionRun_f0f6 {
  strings:
    $key_f0f6 = { a3 99 [2] 87 97 [2] ac bb [2] 82 99 [2] 96 82 [2] 99 98 [2] 87 85 [2] 85 84 [2] 9e 82 [2] 82 85 [2] 9e aa }

  condition:
    any of them
}