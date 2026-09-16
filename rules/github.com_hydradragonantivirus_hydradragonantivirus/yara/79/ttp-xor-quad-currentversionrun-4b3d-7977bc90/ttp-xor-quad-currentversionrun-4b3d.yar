rule TTP_XOR_QUAD_CurrentVersionRun_4b3d {
  strings:
    $key_4b3d = { 18 52 [2] 3c 5c [2] 17 70 [2] 39 52 [2] 2d 49 [2] 22 53 [2] 3c 4e [2] 3e 4f [2] 25 49 [2] 39 4e [2] 25 61 }

  condition:
    any of them
}