rule TTP_XOR_QUAD_CurrentVersionRun_1c3d {
  strings:
    $key_1c3d = { 4f 52 [2] 6b 5c [2] 40 70 [2] 6e 52 [2] 7a 49 [2] 75 53 [2] 6b 4e [2] 69 4f [2] 72 49 [2] 6e 4e [2] 72 61 }

  condition:
    any of them
}