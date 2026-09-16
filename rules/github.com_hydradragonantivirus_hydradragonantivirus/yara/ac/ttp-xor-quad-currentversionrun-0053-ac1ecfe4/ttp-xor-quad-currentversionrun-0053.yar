rule TTP_XOR_QUAD_CurrentVersionRun_0053 {
  strings:
    $key_0053 = { 53 3c [2] 77 32 [2] 5c 1e [2] 72 3c [2] 66 27 [2] 69 3d [2] 77 20 [2] 75 21 [2] 6e 27 [2] 72 20 [2] 6e 0f }

  condition:
    any of them
}