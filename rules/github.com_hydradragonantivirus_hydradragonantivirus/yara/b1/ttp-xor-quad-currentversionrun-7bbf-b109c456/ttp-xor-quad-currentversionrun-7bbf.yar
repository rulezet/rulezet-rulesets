rule TTP_XOR_QUAD_CurrentVersionRun_7bbf {
  strings:
    $key_7bbf = { 28 d0 [2] 0c de [2] 27 f2 [2] 09 d0 [2] 1d cb [2] 12 d1 [2] 0c cc [2] 0e cd [2] 15 cb [2] 09 cc [2] 15 e3 }

  condition:
    any of them
}