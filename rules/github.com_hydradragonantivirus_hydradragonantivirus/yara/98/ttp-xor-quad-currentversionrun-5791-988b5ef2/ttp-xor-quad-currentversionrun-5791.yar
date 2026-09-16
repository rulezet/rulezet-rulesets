rule TTP_XOR_QUAD_CurrentVersionRun_5791 {
  strings:
    $key_5791 = { 04 fe [2] 20 f0 [2] 0b dc [2] 25 fe [2] 31 e5 [2] 3e ff [2] 20 e2 [2] 22 e3 [2] 39 e5 [2] 25 e2 [2] 39 cd }

  condition:
    any of them
}