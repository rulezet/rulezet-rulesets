rule TTP_XOR_QUAD_CurrentVersionRun_70a3 {
  strings:
    $key_70a3 = { 23 cc [2] 07 c2 [2] 2c ee [2] 02 cc [2] 16 d7 [2] 19 cd [2] 07 d0 [2] 05 d1 [2] 1e d7 [2] 02 d0 [2] 1e ff }

  condition:
    any of them
}