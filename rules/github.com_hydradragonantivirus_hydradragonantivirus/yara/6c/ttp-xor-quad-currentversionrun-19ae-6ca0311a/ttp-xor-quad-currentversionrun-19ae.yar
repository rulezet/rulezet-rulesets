rule TTP_XOR_QUAD_CurrentVersionRun_19ae {
  strings:
    $key_19ae = { 4a c1 [2] 6e cf [2] 45 e3 [2] 6b c1 [2] 7f da [2] 70 c0 [2] 6e dd [2] 6c dc [2] 77 da [2] 6b dd [2] 77 f2 }

  condition:
    any of them
}