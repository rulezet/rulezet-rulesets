rule TTP_XOR_QUAD_CurrentVersionRun_05a3 {
  strings:
    $key_05a3 = { 56 cc [2] 72 c2 [2] 59 ee [2] 77 cc [2] 63 d7 [2] 6c cd [2] 72 d0 [2] 70 d1 [2] 6b d7 [2] 77 d0 [2] 6b ff }

  condition:
    any of them
}