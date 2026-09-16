rule TTP_XOR_QUAD_CurrentVersionRun_1791 {
  strings:
    $key_1791 = { 44 fe [2] 60 f0 [2] 4b dc [2] 65 fe [2] 71 e5 [2] 7e ff [2] 60 e2 [2] 62 e3 [2] 79 e5 [2] 65 e2 [2] 79 cd }

  condition:
    any of them
}