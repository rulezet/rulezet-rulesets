rule TTP_XOR_QUAD_CurrentVersionRun_3b3d {
  strings:
    $key_3b3d = { 68 52 [2] 4c 5c [2] 67 70 [2] 49 52 [2] 5d 49 [2] 52 53 [2] 4c 4e [2] 4e 4f [2] 55 49 [2] 49 4e [2] 55 61 }

  condition:
    any of them
}