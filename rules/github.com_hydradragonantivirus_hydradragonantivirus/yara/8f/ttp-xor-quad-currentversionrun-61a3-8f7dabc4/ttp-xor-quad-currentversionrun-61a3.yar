rule TTP_XOR_QUAD_CurrentVersionRun_61a3 {
  strings:
    $key_61a3 = { 32 cc [2] 16 c2 [2] 3d ee [2] 13 cc [2] 07 d7 [2] 08 cd [2] 16 d0 [2] 14 d1 [2] 0f d7 [2] 13 d0 [2] 0f ff }

  condition:
    any of them
}