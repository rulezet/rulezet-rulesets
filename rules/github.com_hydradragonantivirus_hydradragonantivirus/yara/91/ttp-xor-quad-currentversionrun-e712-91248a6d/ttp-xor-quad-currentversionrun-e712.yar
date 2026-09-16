rule TTP_XOR_QUAD_CurrentVersionRun_e712 {
  strings:
    $key_e712 = { b4 7d [2] 90 73 [2] bb 5f [2] 95 7d [2] 81 66 [2] 8e 7c [2] 90 61 [2] 92 60 [2] 89 66 [2] 95 61 [2] 89 4e }

  condition:
    any of them
}