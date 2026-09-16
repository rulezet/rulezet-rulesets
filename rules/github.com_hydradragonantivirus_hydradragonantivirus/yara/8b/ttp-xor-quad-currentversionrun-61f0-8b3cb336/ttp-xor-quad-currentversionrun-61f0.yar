rule TTP_XOR_QUAD_CurrentVersionRun_61f0 {
  strings:
    $key_61f0 = { 32 9f [2] 16 91 [2] 3d bd [2] 13 9f [2] 07 84 [2] 08 9e [2] 16 83 [2] 14 82 [2] 0f 84 [2] 13 83 [2] 0f ac }

  condition:
    any of them
}