rule TTP_XOR_QUAD_CurrentVersionRun_6130 {
  strings:
    $key_6130 = { 32 5f [2] 16 51 [2] 3d 7d [2] 13 5f [2] 07 44 [2] 08 5e [2] 16 43 [2] 14 42 [2] 0f 44 [2] 13 43 [2] 0f 6c }

  condition:
    any of them
}