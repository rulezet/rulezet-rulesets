rule TTP_XOR_QUAD_CurrentVersionRun_615a {
  strings:
    $key_615a = { 32 35 [2] 16 3b [2] 3d 17 [2] 13 35 [2] 07 2e [2] 08 34 [2] 16 29 [2] 14 28 [2] 0f 2e [2] 13 29 [2] 0f 06 }

  condition:
    any of them
}