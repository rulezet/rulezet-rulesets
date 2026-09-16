rule TTP_XOR_QUAD_CurrentVersionRun_7870 {
  strings:
    $key_7870 = { 2b 1f [2] 0f 11 [2] 24 3d [2] 0a 1f [2] 1e 04 [2] 11 1e [2] 0f 03 [2] 0d 02 [2] 16 04 [2] 0a 03 [2] 16 2c }

  condition:
    any of them
}