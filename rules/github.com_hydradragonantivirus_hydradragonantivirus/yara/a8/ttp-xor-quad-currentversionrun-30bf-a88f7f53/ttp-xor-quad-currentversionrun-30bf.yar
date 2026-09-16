rule TTP_XOR_QUAD_CurrentVersionRun_30bf {
  strings:
    $key_30bf = { 63 d0 [2] 47 de [2] 6c f2 [2] 42 d0 [2] 56 cb [2] 59 d1 [2] 47 cc [2] 45 cd [2] 5e cb [2] 42 cc [2] 5e e3 }

  condition:
    any of them
}