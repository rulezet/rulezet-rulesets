rule TTP_XOR_QUAD_CurrentVersionRun_f9bc {
  strings:
    $key_f9bc = { aa d3 [2] 8e dd [2] a5 f1 [2] 8b d3 [2] 9f c8 [2] 90 d2 [2] 8e cf [2] 8c ce [2] 97 c8 [2] 8b cf [2] 97 e0 }

  condition:
    any of them
}