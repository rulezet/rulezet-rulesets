rule TTP_XOR_QUAD_CurrentVersionRun_25a3 {
  strings:
    $key_25a3 = { 76 cc [2] 52 c2 [2] 79 ee [2] 57 cc [2] 43 d7 [2] 4c cd [2] 52 d0 [2] 50 d1 [2] 4b d7 [2] 57 d0 [2] 4b ff }

  condition:
    any of them
}