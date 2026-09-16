rule TTP_XOR_QUAD_CurrentVersionRun_48fd {
  strings:
    $key_48fd = { 1b 92 [2] 3f 9c [2] 14 b0 [2] 3a 92 [2] 2e 89 [2] 21 93 [2] 3f 8e [2] 3d 8f [2] 26 89 [2] 3a 8e [2] 26 a1 }

  condition:
    any of them
}