rule TTP_XOR_QUAD_CurrentVersionRun_1bbf {
  strings:
    $key_1bbf = { 48 d0 [2] 6c de [2] 47 f2 [2] 69 d0 [2] 7d cb [2] 72 d1 [2] 6c cc [2] 6e cd [2] 75 cb [2] 69 cc [2] 75 e3 }

  condition:
    any of them
}