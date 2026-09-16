rule TTP_XOR_QUAD_CurrentVersionRun_14a3 {
  strings:
    $key_14a3 = { 47 cc [2] 63 c2 [2] 48 ee [2] 66 cc [2] 72 d7 [2] 7d cd [2] 63 d0 [2] 61 d1 [2] 7a d7 [2] 66 d0 [2] 7a ff }

  condition:
    any of them
}