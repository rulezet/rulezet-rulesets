rule TTP_XOR_QUAD_CurrentVersionRun_6b53 {
  strings:
    $key_6b53 = { 38 3c [2] 1c 32 [2] 37 1e [2] 19 3c [2] 0d 27 [2] 02 3d [2] 1c 20 [2] 1e 21 [2] 05 27 [2] 19 20 [2] 05 0f }

  condition:
    any of them
}