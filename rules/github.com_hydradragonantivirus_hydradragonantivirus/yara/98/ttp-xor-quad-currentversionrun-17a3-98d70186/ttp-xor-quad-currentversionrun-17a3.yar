rule TTP_XOR_QUAD_CurrentVersionRun_17a3 {
  strings:
    $key_17a3 = { 44 cc [2] 60 c2 [2] 4b ee [2] 65 cc [2] 71 d7 [2] 7e cd [2] 60 d0 [2] 62 d1 [2] 79 d7 [2] 65 d0 [2] 79 ff }

  condition:
    any of them
}