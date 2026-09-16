rule TTP_XOR_QUAD_CurrentVersionRun_f1f6 {
  strings:
    $key_f1f6 = { a2 99 [2] 86 97 [2] ad bb [2] 83 99 [2] 97 82 [2] 98 98 [2] 86 85 [2] 84 84 [2] 9f 82 [2] 83 85 [2] 9f aa }

  condition:
    any of them
}