rule TTP_XOR_QUAD_CurrentVersionRun_2fae {
  strings:
    $key_2fae = { 7c c1 [2] 58 cf [2] 73 e3 [2] 5d c1 [2] 49 da [2] 46 c0 [2] 58 dd [2] 5a dc [2] 41 da [2] 5d dd [2] 41 f2 }

  condition:
    any of them
}