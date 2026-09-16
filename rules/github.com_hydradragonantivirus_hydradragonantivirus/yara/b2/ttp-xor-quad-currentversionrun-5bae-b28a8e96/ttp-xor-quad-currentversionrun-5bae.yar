rule TTP_XOR_QUAD_CurrentVersionRun_5bae {
  strings:
    $key_5bae = { 08 c1 [2] 2c cf [2] 07 e3 [2] 29 c1 [2] 3d da [2] 32 c0 [2] 2c dd [2] 2e dc [2] 35 da [2] 29 dd [2] 35 f2 }

  condition:
    any of them
}