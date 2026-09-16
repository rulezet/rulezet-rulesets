rule TTP_XOR_QUAD_CurrentVersionRun_41a3 {
  strings:
    $key_41a3 = { 12 cc [2] 36 c2 [2] 1d ee [2] 33 cc [2] 27 d7 [2] 28 cd [2] 36 d0 [2] 34 d1 [2] 2f d7 [2] 33 d0 [2] 2f ff }

  condition:
    any of them
}