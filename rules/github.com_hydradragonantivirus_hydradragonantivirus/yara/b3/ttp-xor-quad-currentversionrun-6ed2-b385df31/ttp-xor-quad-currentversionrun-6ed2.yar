rule TTP_XOR_QUAD_CurrentVersionRun_6ed2 {
  strings:
    $key_6ed2 = { 3d bd [2] 19 b3 [2] 32 9f [2] 1c bd [2] 08 a6 [2] 07 bc [2] 19 a1 [2] 1b a0 [2] 00 a6 [2] 1c a1 [2] 00 8e }

  condition:
    any of them
}