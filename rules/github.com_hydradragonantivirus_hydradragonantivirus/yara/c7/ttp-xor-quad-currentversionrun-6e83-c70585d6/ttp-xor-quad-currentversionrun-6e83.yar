rule TTP_XOR_QUAD_CurrentVersionRun_6e83 {
  strings:
    $key_6e83 = { 3d ec [2] 19 e2 [2] 32 ce [2] 1c ec [2] 08 f7 [2] 07 ed [2] 19 f0 [2] 1b f1 [2] 00 f7 [2] 1c f0 [2] 00 df }

  condition:
    any of them
}