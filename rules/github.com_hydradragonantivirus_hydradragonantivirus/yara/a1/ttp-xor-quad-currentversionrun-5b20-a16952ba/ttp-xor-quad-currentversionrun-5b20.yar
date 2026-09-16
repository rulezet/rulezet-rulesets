rule TTP_XOR_QUAD_CurrentVersionRun_5b20 {
  strings:
    $key_5b20 = { 08 4f [2] 2c 41 [2] 07 6d [2] 29 4f [2] 3d 54 [2] 32 4e [2] 2c 53 [2] 2e 52 [2] 35 54 [2] 29 53 [2] 35 7c }

  condition:
    any of them
}