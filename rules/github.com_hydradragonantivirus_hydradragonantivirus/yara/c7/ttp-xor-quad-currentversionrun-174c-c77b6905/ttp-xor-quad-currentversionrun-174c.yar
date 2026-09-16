rule TTP_XOR_QUAD_CurrentVersionRun_174c {
  strings:
    $key_174c = { 44 23 [2] 60 2d [2] 4b 01 [2] 65 23 [2] 71 38 [2] 7e 22 [2] 60 3f [2] 62 3e [2] 79 38 [2] 65 3f [2] 79 10 }

  condition:
    any of them
}