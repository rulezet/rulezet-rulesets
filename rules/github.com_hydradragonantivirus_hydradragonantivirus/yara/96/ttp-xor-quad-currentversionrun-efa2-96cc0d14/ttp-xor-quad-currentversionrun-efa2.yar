rule TTP_XOR_QUAD_CurrentVersionRun_efa2 {
  strings:
    $key_efa2 = { bc cd [2] 98 c3 [2] b3 ef [2] 9d cd [2] 89 d6 [2] 86 cc [2] 98 d1 [2] 9a d0 [2] 81 d6 [2] 9d d1 [2] 81 fe }

  condition:
    any of them
}