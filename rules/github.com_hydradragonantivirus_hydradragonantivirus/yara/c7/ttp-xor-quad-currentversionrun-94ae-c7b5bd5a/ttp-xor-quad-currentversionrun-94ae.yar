rule TTP_XOR_QUAD_CurrentVersionRun_94ae {
  strings:
    $key_94ae = { c7 c1 [2] e3 cf [2] c8 e3 [2] e6 c1 [2] f2 da [2] fd c0 [2] e3 dd [2] e1 dc [2] fa da [2] e6 dd [2] fa f2 }

  condition:
    any of them
}