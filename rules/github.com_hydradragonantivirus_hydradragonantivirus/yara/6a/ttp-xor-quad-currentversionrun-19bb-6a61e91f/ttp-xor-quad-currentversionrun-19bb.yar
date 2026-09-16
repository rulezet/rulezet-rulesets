rule TTP_XOR_QUAD_CurrentVersionRun_19bb {
  strings:
    $key_19bb = { 4a d4 [2] 6e da [2] 45 f6 [2] 6b d4 [2] 7f cf [2] 70 d5 [2] 6e c8 [2] 6c c9 [2] 77 cf [2] 6b c8 [2] 77 e7 }

  condition:
    any of them
}