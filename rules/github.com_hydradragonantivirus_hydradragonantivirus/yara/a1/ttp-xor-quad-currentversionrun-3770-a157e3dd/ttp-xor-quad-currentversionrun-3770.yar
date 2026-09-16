rule TTP_XOR_QUAD_CurrentVersionRun_3770 {
  strings:
    $key_3770 = { 64 1f [2] 40 11 [2] 6b 3d [2] 45 1f [2] 51 04 [2] 5e 1e [2] 40 03 [2] 42 02 [2] 59 04 [2] 45 03 [2] 59 2c }

  condition:
    any of them
}