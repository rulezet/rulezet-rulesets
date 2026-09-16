rule TTP_XOR_QUAD_CurrentVersionRun_6c3d {
  strings:
    $key_6c3d = { 3f 52 [2] 1b 5c [2] 30 70 [2] 1e 52 [2] 0a 49 [2] 05 53 [2] 1b 4e [2] 19 4f [2] 02 49 [2] 1e 4e [2] 02 61 }

  condition:
    any of them
}