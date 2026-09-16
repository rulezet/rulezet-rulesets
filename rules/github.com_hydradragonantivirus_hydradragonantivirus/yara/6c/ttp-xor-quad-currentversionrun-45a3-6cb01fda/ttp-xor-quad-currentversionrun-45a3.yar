rule TTP_XOR_QUAD_CurrentVersionRun_45a3 {
  strings:
    $key_45a3 = { 16 cc [2] 32 c2 [2] 19 ee [2] 37 cc [2] 23 d7 [2] 2c cd [2] 32 d0 [2] 30 d1 [2] 2b d7 [2] 37 d0 [2] 2b ff }

  condition:
    any of them
}