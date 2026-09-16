rule TTP_XOR_QUAD_CurrentVersionRun_eda2 {
  strings:
    $key_eda2 = { be cd [2] 9a c3 [2] b1 ef [2] 9f cd [2] 8b d6 [2] 84 cc [2] 9a d1 [2] 98 d0 [2] 83 d6 [2] 9f d1 [2] 83 fe }

  condition:
    any of them
}