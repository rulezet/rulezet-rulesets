rule TTP_XOR_QUAD_CurrentVersionRun_214c {
  strings:
    $key_214c = { 72 23 [2] 56 2d [2] 7d 01 [2] 53 23 [2] 47 38 [2] 48 22 [2] 56 3f [2] 54 3e [2] 4f 38 [2] 53 3f [2] 4f 10 }

  condition:
    any of them
}