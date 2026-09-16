rule TTP_XOR_QUAD_CurrentVersionRun_16bf {
  strings:
    $key_16bf = { 45 d0 [2] 61 de [2] 4a f2 [2] 64 d0 [2] 70 cb [2] 7f d1 [2] 61 cc [2] 63 cd [2] 78 cb [2] 64 cc [2] 78 e3 }

  condition:
    any of them
}