rule TTP_XOR_QUAD_CurrentVersionRun_2051 {
  strings:
    $key_2051 = { 73 3e [2] 57 30 [2] 7c 1c [2] 52 3e [2] 46 25 [2] 49 3f [2] 57 22 [2] 55 23 [2] 4e 25 [2] 52 22 [2] 4e 0d }

  condition:
    any of them
}