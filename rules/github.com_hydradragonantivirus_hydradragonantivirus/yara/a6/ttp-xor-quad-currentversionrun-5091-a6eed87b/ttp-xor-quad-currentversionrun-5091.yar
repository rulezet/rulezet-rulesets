rule TTP_XOR_QUAD_CurrentVersionRun_5091 {
  strings:
    $key_5091 = { 03 fe [2] 27 f0 [2] 0c dc [2] 22 fe [2] 36 e5 [2] 39 ff [2] 27 e2 [2] 25 e3 [2] 3e e5 [2] 22 e2 [2] 3e cd }

  condition:
    any of them
}