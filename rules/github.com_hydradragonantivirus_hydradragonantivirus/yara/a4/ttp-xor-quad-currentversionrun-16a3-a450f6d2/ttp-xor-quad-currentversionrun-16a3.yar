rule TTP_XOR_QUAD_CurrentVersionRun_16a3 {
  strings:
    $key_16a3 = { 45 cc [2] 61 c2 [2] 4a ee [2] 64 cc [2] 70 d7 [2] 7f cd [2] 61 d0 [2] 63 d1 [2] 78 d7 [2] 64 d0 [2] 78 ff }

  condition:
    any of them
}