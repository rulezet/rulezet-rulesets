rule TTP_XOR_QUAD_CurrentVersionRun_edba {
  strings:
    $key_edba = { be d5 [2] 9a db [2] b1 f7 [2] 9f d5 [2] 8b ce [2] 84 d4 [2] 9a c9 [2] 98 c8 [2] 83 ce [2] 9f c9 [2] 83 e6 }

  condition:
    any of them
}