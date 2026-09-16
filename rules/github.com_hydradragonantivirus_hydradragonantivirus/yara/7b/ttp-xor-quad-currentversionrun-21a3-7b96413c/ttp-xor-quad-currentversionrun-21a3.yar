rule TTP_XOR_QUAD_CurrentVersionRun_21a3 {
  strings:
    $key_21a3 = { 72 cc [2] 56 c2 [2] 7d ee [2] 53 cc [2] 47 d7 [2] 48 cd [2] 56 d0 [2] 54 d1 [2] 4f d7 [2] 53 d0 [2] 4f ff }

  condition:
    any of them
}