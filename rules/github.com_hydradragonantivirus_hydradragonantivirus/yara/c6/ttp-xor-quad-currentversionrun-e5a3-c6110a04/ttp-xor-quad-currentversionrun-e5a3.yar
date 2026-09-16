rule TTP_XOR_QUAD_CurrentVersionRun_e5a3 {
  strings:
    $key_e5a3 = { b6 cc [2] 92 c2 [2] b9 ee [2] 97 cc [2] 83 d7 [2] 8c cd [2] 92 d0 [2] 90 d1 [2] 8b d7 [2] 97 d0 [2] 8b ff }

  condition:
    any of them
}