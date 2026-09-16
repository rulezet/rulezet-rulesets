rule TTP_XOR_QUAD_CurrentVersionRun_6aae {
  strings:
    $key_6aae = { 39 c1 [2] 1d cf [2] 36 e3 [2] 18 c1 [2] 0c da [2] 03 c0 [2] 1d dd [2] 1f dc [2] 04 da [2] 18 dd [2] 04 f2 }

  condition:
    any of them
}