rule TTP_XOR_QUAD_CurrentVersionRun_0f70 {
  strings:
    $key_0f70 = { 5c 1f [2] 78 11 [2] 53 3d [2] 7d 1f [2] 69 04 [2] 66 1e [2] 78 03 [2] 7a 02 [2] 61 04 [2] 7d 03 [2] 61 2c }

  condition:
    any of them
}