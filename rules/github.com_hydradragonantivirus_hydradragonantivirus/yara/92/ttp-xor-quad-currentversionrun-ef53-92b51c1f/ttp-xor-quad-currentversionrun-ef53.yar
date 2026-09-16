rule TTP_XOR_QUAD_CurrentVersionRun_ef53 {
  strings:
    $key_ef53 = { bc 3c [2] 98 32 [2] b3 1e [2] 9d 3c [2] 89 27 [2] 86 3d [2] 98 20 [2] 9a 21 [2] 81 27 [2] 9d 20 [2] 81 0f }

  condition:
    any of them
}