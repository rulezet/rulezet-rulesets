rule TTP_XOR_QUAD_CurrentVersionRun_3d33 {
  strings:
    $key_3d33 = { 6e 5c [2] 4a 52 [2] 61 7e [2] 4f 5c [2] 5b 47 [2] 54 5d [2] 4a 40 [2] 48 41 [2] 53 47 [2] 4f 40 [2] 53 6f }

  condition:
    any of them
}