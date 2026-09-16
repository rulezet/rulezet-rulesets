rule TTP_XOR_QUAD_CurrentVersionRun_16be {
  strings:
    $key_16be = { 45 d1 [2] 61 df [2] 4a f3 [2] 64 d1 [2] 70 ca [2] 7f d0 [2] 61 cd [2] 63 cc [2] 78 ca [2] 64 cd [2] 78 e2 }

  condition:
    any of them
}