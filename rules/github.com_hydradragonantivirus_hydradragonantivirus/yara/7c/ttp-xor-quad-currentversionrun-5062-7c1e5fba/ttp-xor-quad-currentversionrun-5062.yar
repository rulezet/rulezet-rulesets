rule TTP_XOR_QUAD_CurrentVersionRun_5062 {
  strings:
    $key_5062 = { 03 0d [2] 27 03 [2] 0c 2f [2] 22 0d [2] 36 16 [2] 39 0c [2] 27 11 [2] 25 10 [2] 3e 16 [2] 22 11 [2] 3e 3e }

  condition:
    any of them
}