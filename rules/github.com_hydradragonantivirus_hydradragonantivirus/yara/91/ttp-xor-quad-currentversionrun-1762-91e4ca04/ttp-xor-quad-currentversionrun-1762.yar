rule TTP_XOR_QUAD_CurrentVersionRun_1762 {
  strings:
    $key_1762 = { 44 0d [2] 60 03 [2] 4b 2f [2] 65 0d [2] 71 16 [2] 7e 0c [2] 60 11 [2] 62 10 [2] 79 16 [2] 65 11 [2] 79 3e }

  condition:
    any of them
}