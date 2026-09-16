rule TTP_XOR_QUAD_CurrentVersionRun_7f3d {
  strings:
    $key_7f3d = { 2c 52 [2] 08 5c [2] 23 70 [2] 0d 52 [2] 19 49 [2] 16 53 [2] 08 4e [2] 0a 4f [2] 11 49 [2] 0d 4e [2] 11 61 }

  condition:
    any of them
}