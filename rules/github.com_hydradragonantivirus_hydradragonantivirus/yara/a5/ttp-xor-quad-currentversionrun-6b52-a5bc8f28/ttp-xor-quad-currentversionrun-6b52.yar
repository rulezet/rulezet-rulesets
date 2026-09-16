rule TTP_XOR_QUAD_CurrentVersionRun_6b52 {
  strings:
    $key_6b52 = { 38 3d [2] 1c 33 [2] 37 1f [2] 19 3d [2] 0d 26 [2] 02 3c [2] 1c 21 [2] 1e 20 [2] 05 26 [2] 19 21 [2] 05 0e }

  condition:
    any of them
}