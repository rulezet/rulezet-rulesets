rule TTP_XOR_QUAD_CurrentVersionRun_69ae {
  strings:
    $key_69ae = { 3a c1 [2] 1e cf [2] 35 e3 [2] 1b c1 [2] 0f da [2] 00 c0 [2] 1e dd [2] 1c dc [2] 07 da [2] 1b dd [2] 07 f2 }

  condition:
    any of them
}