rule TTP_XOR_QUAD_CurrentVersionRun_f7f7 {
  strings:
    $key_f7f7 = { a4 98 [2] 80 96 [2] ab ba [2] 85 98 [2] 91 83 [2] 9e 99 [2] 80 84 [2] 82 85 [2] 99 83 [2] 85 84 [2] 99 ab }

  condition:
    any of them
}