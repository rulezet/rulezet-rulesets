rule TTP_XOR_QUAD_CurrentVersionRun_134c {
  strings:
    $key_134c = { 40 23 [2] 64 2d [2] 4f 01 [2] 61 23 [2] 75 38 [2] 7a 22 [2] 64 3f [2] 66 3e [2] 7d 38 [2] 61 3f [2] 7d 10 }

  condition:
    any of them
}