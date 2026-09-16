rule TTP_XOR_QUAD_CurrentVersionRun_0d61 {
  strings:
    $key_0d61 = { 5e 0e [2] 7a 00 [2] 51 2c [2] 7f 0e [2] 6b 15 [2] 64 0f [2] 7a 12 [2] 78 13 [2] 63 15 [2] 7f 12 [2] 63 3d }

  condition:
    any of them
}