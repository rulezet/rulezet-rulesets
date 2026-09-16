rule TTP_XOR_QUAD_CurrentVersionRun_6efd {
  strings:
    $key_6efd = { 3d 92 [2] 19 9c [2] 32 b0 [2] 1c 92 [2] 08 89 [2] 07 93 [2] 19 8e [2] 1b 8f [2] 00 89 [2] 1c 8e [2] 00 a1 }

  condition:
    any of them
}