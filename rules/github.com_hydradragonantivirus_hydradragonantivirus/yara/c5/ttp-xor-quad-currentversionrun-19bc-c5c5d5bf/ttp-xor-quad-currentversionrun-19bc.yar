rule TTP_XOR_QUAD_CurrentVersionRun_19bc {
  strings:
    $key_19bc = { 4a d3 [2] 6e dd [2] 45 f1 [2] 6b d3 [2] 7f c8 [2] 70 d2 [2] 6e cf [2] 6c ce [2] 77 c8 [2] 6b cf [2] 77 e0 }

  condition:
    any of them
}