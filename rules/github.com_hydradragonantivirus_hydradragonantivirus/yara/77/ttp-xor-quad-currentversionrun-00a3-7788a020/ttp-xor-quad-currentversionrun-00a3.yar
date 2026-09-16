rule TTP_XOR_QUAD_CurrentVersionRun_00a3 {
  strings:
    $key_00a3 = { 53 cc [2] 77 c2 [2] 5c ee [2] 72 cc [2] 66 d7 [2] 69 cd [2] 77 d0 [2] 75 d1 [2] 6e d7 [2] 72 d0 [2] 6e ff }

  condition:
    any of them
}