rule TTP_XOR_QUAD_CurrentVersionRun_72bf {
  strings:
    $key_72bf = { 21 d0 [2] 05 de [2] 2e f2 [2] 00 d0 [2] 14 cb [2] 1b d1 [2] 05 cc [2] 07 cd [2] 1c cb [2] 00 cc [2] 1c e3 }

  condition:
    any of them
}