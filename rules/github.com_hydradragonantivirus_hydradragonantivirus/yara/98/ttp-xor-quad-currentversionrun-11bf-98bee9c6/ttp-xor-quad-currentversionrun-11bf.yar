rule TTP_XOR_QUAD_CurrentVersionRun_11bf {
  strings:
    $key_11bf = { 42 d0 [2] 66 de [2] 4d f2 [2] 63 d0 [2] 77 cb [2] 78 d1 [2] 66 cc [2] 64 cd [2] 7f cb [2] 63 cc [2] 7f e3 }

  condition:
    any of them
}