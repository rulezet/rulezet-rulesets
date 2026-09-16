rule TTP_XOR_QUAD_CurrentVersionRun_0f4c {
  strings:
    $key_0f4c = { 5c 23 [2] 78 2d [2] 53 01 [2] 7d 23 [2] 69 38 [2] 66 22 [2] 78 3f [2] 7a 3e [2] 61 38 [2] 7d 3f [2] 61 10 }

  condition:
    any of them
}