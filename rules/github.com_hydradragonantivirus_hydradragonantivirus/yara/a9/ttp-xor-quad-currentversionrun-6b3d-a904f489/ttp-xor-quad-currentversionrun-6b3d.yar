rule TTP_XOR_QUAD_CurrentVersionRun_6b3d {
  strings:
    $key_6b3d = { 38 52 [2] 1c 5c [2] 37 70 [2] 19 52 [2] 0d 49 [2] 02 53 [2] 1c 4e [2] 1e 4f [2] 05 49 [2] 19 4e [2] 05 61 }

  condition:
    any of them
}