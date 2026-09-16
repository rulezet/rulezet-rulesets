rule TTP_XOR_QUAD_CurrentVersionRun_2bbf {
  strings:
    $key_2bbf = { 78 d0 [2] 5c de [2] 77 f2 [2] 59 d0 [2] 4d cb [2] 42 d1 [2] 5c cc [2] 5e cd [2] 45 cb [2] 59 cc [2] 45 e3 }

  condition:
    any of them
}