rule TTP_XOR_QUAD_CurrentVersionRun_6182 {
  strings:
    $key_6182 = { 32 ed [2] 16 e3 [2] 3d cf [2] 13 ed [2] 07 f6 [2] 08 ec [2] 16 f1 [2] 14 f0 [2] 0f f6 [2] 13 f1 [2] 0f de }

  condition:
    any of them
}