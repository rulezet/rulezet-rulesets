rule TTP_XOR_QUAD_CurrentVersionRun_5e3d {
  strings:
    $key_5e3d = { 0d 52 [2] 29 5c [2] 02 70 [2] 2c 52 [2] 38 49 [2] 37 53 [2] 29 4e [2] 2b 4f [2] 30 49 [2] 2c 4e [2] 30 61 }

  condition:
    any of them
}