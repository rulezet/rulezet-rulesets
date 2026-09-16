rule TTP_XOR_QUAD_CurrentVersionRun_3d32 {
  strings:
    $key_3d32 = { 6e 5d [2] 4a 53 [2] 61 7f [2] 4f 5d [2] 5b 46 [2] 54 5c [2] 4a 41 [2] 48 40 [2] 53 46 [2] 4f 41 [2] 53 6e }

  condition:
    any of them
}