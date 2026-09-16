rule TTP_XOR_QUAD_CurrentVersionRun_0961 {
  strings:
    $key_0961 = { 5a 0e [2] 7e 00 [2] 55 2c [2] 7b 0e [2] 6f 15 [2] 60 0f [2] 7e 12 [2] 7c 13 [2] 67 15 [2] 7b 12 [2] 67 3d }

  condition:
    any of them
}