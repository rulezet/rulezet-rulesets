rule TTP_XOR_QUAD_CurrentVersionRun_39ae {
  strings:
    $key_39ae = { 6a c1 [2] 4e cf [2] 65 e3 [2] 4b c1 [2] 5f da [2] 50 c0 [2] 4e dd [2] 4c dc [2] 57 da [2] 4b dd [2] 57 f2 }

  condition:
    any of them
}