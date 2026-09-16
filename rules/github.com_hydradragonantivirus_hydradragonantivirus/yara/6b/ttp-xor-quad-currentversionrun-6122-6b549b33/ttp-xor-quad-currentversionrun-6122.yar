rule TTP_XOR_QUAD_CurrentVersionRun_6122 {
  strings:
    $key_6122 = { 32 4d [2] 16 43 [2] 3d 6f [2] 13 4d [2] 07 56 [2] 08 4c [2] 16 51 [2] 14 50 [2] 0f 56 [2] 13 51 [2] 0f 7e }

  condition:
    any of them
}