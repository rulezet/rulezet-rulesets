rule TTP_XOR_QUAD_CurrentVersionRun_11a3 {
  strings:
    $key_11a3 = { 42 cc [2] 66 c2 [2] 4d ee [2] 63 cc [2] 77 d7 [2] 78 cd [2] 66 d0 [2] 64 d1 [2] 7f d7 [2] 63 d0 [2] 7f ff }

  condition:
    any of them
}