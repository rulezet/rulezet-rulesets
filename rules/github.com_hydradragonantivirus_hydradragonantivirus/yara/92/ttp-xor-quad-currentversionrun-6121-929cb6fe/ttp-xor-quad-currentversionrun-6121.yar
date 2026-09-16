rule TTP_XOR_QUAD_CurrentVersionRun_6121 {
  strings:
    $key_6121 = { 32 4e [2] 16 40 [2] 3d 6c [2] 13 4e [2] 07 55 [2] 08 4f [2] 16 52 [2] 14 53 [2] 0f 55 [2] 13 52 [2] 0f 7d }

  condition:
    any of them
}