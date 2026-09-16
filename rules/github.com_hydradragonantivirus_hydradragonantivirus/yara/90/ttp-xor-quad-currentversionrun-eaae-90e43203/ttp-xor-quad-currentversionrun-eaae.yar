rule TTP_XOR_QUAD_CurrentVersionRun_eaae {
  strings:
    $key_eaae = { b9 c1 [2] 9d cf [2] b6 e3 [2] 98 c1 [2] 8c da [2] 83 c0 [2] 9d dd [2] 9f dc [2] 84 da [2] 98 dd [2] 84 f2 }

  condition:
    any of them
}