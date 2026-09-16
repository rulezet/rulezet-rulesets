rule TTP_XOR_QUAD_CurrentVersionRun_61a2 {
  strings:
    $key_61a2 = { 32 cd [2] 16 c3 [2] 3d ef [2] 13 cd [2] 07 d6 [2] 08 cc [2] 16 d1 [2] 14 d0 [2] 0f d6 [2] 13 d1 [2] 0f fe }

  condition:
    any of them
}