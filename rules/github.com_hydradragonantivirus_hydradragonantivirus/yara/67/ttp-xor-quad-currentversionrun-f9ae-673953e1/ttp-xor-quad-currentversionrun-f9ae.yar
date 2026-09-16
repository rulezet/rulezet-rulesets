rule TTP_XOR_QUAD_CurrentVersionRun_f9ae {
  strings:
    $key_f9ae = { aa c1 [2] 8e cf [2] a5 e3 [2] 8b c1 [2] 9f da [2] 90 c0 [2] 8e dd [2] 8c dc [2] 97 da [2] 8b dd [2] 97 f2 }

  condition:
    any of them
}