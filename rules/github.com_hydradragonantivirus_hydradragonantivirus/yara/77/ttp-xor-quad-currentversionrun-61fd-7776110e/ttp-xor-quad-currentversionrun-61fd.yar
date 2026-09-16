rule TTP_XOR_QUAD_CurrentVersionRun_61fd {
  strings:
    $key_61fd = { 32 92 [2] 16 9c [2] 3d b0 [2] 13 92 [2] 07 89 [2] 08 93 [2] 16 8e [2] 14 8f [2] 0f 89 [2] 13 8e [2] 0f a1 }

  condition:
    any of them
}