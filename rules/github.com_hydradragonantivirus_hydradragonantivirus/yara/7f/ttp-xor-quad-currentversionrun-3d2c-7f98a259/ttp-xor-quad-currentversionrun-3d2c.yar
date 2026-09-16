rule TTP_XOR_QUAD_CurrentVersionRun_3d2c {
  strings:
    $key_3d2c = { 6e 43 [2] 4a 4d [2] 61 61 [2] 4f 43 [2] 5b 58 [2] 54 42 [2] 4a 5f [2] 48 5e [2] 53 58 [2] 4f 5f [2] 53 70 }

  condition:
    any of them
}