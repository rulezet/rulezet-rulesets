rule TTP_XOR_QUAD_CurrentVersionRun_3f70 {
  strings:
    $key_3f70 = { 6c 1f [2] 48 11 [2] 63 3d [2] 4d 1f [2] 59 04 [2] 56 1e [2] 48 03 [2] 4a 02 [2] 51 04 [2] 4d 03 [2] 51 2c }

  condition:
    any of them
}