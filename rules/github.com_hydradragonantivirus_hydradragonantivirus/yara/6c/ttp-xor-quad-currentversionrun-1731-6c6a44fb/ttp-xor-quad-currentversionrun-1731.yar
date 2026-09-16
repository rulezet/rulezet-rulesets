rule TTP_XOR_QUAD_CurrentVersionRun_1731 {
  strings:
    $key_1731 = { 44 5e [2] 60 50 [2] 4b 7c [2] 65 5e [2] 71 45 [2] 7e 5f [2] 60 42 [2] 62 43 [2] 79 45 [2] 65 42 [2] 79 6d }

  condition:
    any of them
}