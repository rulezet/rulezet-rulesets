rule TTP_XOR_QUAD_CurrentVersionRun_1433 {
  strings:
    $key_1433 = { 47 5c [2] 63 52 [2] 48 7e [2] 66 5c [2] 72 47 [2] 7d 5d [2] 63 40 [2] 61 41 [2] 7a 47 [2] 66 40 [2] 7a 6f }

  condition:
    any of them
}