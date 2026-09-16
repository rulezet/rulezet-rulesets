rule TTP_XOR_QUAD_CurrentVersionRun_7062 {
  strings:
    $key_7062 = { 23 0d [2] 07 03 [2] 2c 2f [2] 02 0d [2] 16 16 [2] 19 0c [2] 07 11 [2] 05 10 [2] 1e 16 [2] 02 11 [2] 1e 3e }

  condition:
    any of them
}