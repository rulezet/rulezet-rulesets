rule TTP_XOR_QUAD_CurrentVersionRun_376d {
  strings:
    $key_376d = { 64 02 [2] 40 0c [2] 6b 20 [2] 45 02 [2] 51 19 [2] 5e 03 [2] 40 1e [2] 42 1f [2] 59 19 [2] 45 1e [2] 59 31 }

  condition:
    any of them
}