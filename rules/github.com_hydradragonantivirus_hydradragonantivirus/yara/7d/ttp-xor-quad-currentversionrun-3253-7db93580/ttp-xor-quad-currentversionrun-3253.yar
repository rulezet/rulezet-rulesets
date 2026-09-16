rule TTP_XOR_QUAD_CurrentVersionRun_3253 {
  strings:
    $key_3253 = { 61 3c [2] 45 32 [2] 6e 1e [2] 40 3c [2] 54 27 [2] 5b 3d [2] 45 20 [2] 47 21 [2] 5c 27 [2] 40 20 [2] 5c 0f }

  condition:
    any of them
}