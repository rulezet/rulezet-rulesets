rule TTP_XOR_QUAD_CurrentVersionRun_e7a2 {
  strings:
    $key_e7a2 = { b4 cd [2] 90 c3 [2] bb ef [2] 95 cd [2] 81 d6 [2] 8e cc [2] 90 d1 [2] 92 d0 [2] 89 d6 [2] 95 d1 [2] 89 fe }

  condition:
    any of them
}