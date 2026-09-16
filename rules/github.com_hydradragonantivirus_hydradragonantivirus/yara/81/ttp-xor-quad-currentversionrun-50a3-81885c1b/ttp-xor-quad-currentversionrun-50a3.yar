rule TTP_XOR_QUAD_CurrentVersionRun_50a3 {
  strings:
    $key_50a3 = { 03 cc [2] 27 c2 [2] 0c ee [2] 22 cc [2] 36 d7 [2] 39 cd [2] 27 d0 [2] 25 d1 [2] 3e d7 [2] 22 d0 [2] 3e ff }

  condition:
    any of them
}