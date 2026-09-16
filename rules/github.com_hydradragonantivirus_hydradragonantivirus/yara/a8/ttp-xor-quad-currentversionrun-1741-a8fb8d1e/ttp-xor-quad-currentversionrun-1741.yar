rule TTP_XOR_QUAD_CurrentVersionRun_1741 {
  strings:
    $key_1741 = { 44 2e [2] 60 20 [2] 4b 0c [2] 65 2e [2] 71 35 [2] 7e 2f [2] 60 32 [2] 62 33 [2] 79 35 [2] 65 32 [2] 79 1d }

  condition:
    any of them
}