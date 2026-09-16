rule TTP_XOR_QUAD_CurrentVersionRun_3d7c {
  strings:
    $key_3d7c = { 6e 13 [2] 4a 1d [2] 61 31 [2] 4f 13 [2] 5b 08 [2] 54 12 [2] 4a 0f [2] 48 0e [2] 53 08 [2] 4f 0f [2] 53 20 }

  condition:
    any of them
}