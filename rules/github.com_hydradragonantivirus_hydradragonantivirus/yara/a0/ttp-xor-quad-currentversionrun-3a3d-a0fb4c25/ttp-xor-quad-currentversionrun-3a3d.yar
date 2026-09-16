rule TTP_XOR_QUAD_CurrentVersionRun_3a3d {
  strings:
    $key_3a3d = { 69 52 [2] 4d 5c [2] 66 70 [2] 48 52 [2] 5c 49 [2] 53 53 [2] 4d 4e [2] 4f 4f [2] 54 49 [2] 48 4e [2] 54 61 }

  condition:
    any of them
}