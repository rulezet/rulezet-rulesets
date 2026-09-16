rule TTP_XOR_QUAD_CurrentVersionRun_2091 {
  strings:
    $key_2091 = { 73 fe [2] 57 f0 [2] 7c dc [2] 52 fe [2] 46 e5 [2] 49 ff [2] 57 e2 [2] 55 e3 [2] 4e e5 [2] 52 e2 [2] 4e cd }

  condition:
    any of them
}