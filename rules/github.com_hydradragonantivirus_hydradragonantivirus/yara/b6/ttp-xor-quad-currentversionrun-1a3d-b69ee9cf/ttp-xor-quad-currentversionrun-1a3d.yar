rule TTP_XOR_QUAD_CurrentVersionRun_1a3d {
  strings:
    $key_1a3d = { 49 52 [2] 6d 5c [2] 46 70 [2] 68 52 [2] 7c 49 [2] 73 53 [2] 6d 4e [2] 6f 4f [2] 74 49 [2] 68 4e [2] 74 61 }

  condition:
    any of them
}