rule TTP_XOR_QUAD_CurrentVersionRun_0091 {
  strings:
    $key_0091 = { 53 fe [2] 77 f0 [2] 5c dc [2] 72 fe [2] 66 e5 [2] 69 ff [2] 77 e2 [2] 75 e3 [2] 6e e5 [2] 72 e2 [2] 6e cd }

  condition:
    any of them
}