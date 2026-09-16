rule TTP_XOR_QUAD_CurrentVersionRun_e722 {
  strings:
    $key_e722 = { b4 4d [2] 90 43 [2] bb 6f [2] 95 4d [2] 81 56 [2] 8e 4c [2] 90 51 [2] 92 50 [2] 89 56 [2] 95 51 [2] 89 7e }

  condition:
    any of them
}