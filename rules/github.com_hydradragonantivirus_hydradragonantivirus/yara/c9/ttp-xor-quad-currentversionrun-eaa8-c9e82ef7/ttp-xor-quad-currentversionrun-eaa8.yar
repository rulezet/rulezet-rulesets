rule TTP_XOR_QUAD_CurrentVersionRun_eaa8 {
  strings:
    $key_eaa8 = { b9 c7 [2] 9d c9 [2] b6 e5 [2] 98 c7 [2] 8c dc [2] 83 c6 [2] 9d db [2] 9f da [2] 84 dc [2] 98 db [2] 84 f4 }

  condition:
    any of them
}