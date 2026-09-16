rule TTP_XOR_QUAD_CurrentVersionRun_71a3 {
  strings:
    $key_71a3 = { 22 cc [2] 06 c2 [2] 2d ee [2] 03 cc [2] 17 d7 [2] 18 cd [2] 06 d0 [2] 04 d1 [2] 1f d7 [2] 03 d0 [2] 1f ff }

  condition:
    any of them
}