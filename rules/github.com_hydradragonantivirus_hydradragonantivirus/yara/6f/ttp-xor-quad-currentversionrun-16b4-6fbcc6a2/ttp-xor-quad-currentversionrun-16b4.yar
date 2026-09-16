rule TTP_XOR_QUAD_CurrentVersionRun_16b4 {
  strings:
    $key_16b4 = { 45 db [2] 61 d5 [2] 4a f9 [2] 64 db [2] 70 c0 [2] 7f da [2] 61 c7 [2] 63 c6 [2] 78 c0 [2] 64 c7 [2] 78 e8 }

  condition:
    any of them
}