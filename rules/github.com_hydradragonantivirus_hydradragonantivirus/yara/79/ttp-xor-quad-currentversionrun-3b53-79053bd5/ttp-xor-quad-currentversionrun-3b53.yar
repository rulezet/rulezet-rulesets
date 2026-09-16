rule TTP_XOR_QUAD_CurrentVersionRun_3b53 {
  strings:
    $key_3b53 = { 68 3c [2] 4c 32 [2] 67 1e [2] 49 3c [2] 5d 27 [2] 52 3d [2] 4c 20 [2] 4e 21 [2] 55 27 [2] 49 20 [2] 55 0f }

  condition:
    any of them
}