rule TTP_XOR_QUAD_CurrentVersionRun_e702 {
  strings:
    $key_e702 = { b4 6d [2] 90 63 [2] bb 4f [2] 95 6d [2] 81 76 [2] 8e 6c [2] 90 71 [2] 92 70 [2] 89 76 [2] 95 71 [2] 89 5e }

  condition:
    any of them
}