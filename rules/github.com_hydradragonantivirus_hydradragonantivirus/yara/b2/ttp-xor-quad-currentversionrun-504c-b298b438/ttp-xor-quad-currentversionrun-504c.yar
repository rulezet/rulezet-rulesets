rule TTP_XOR_QUAD_CurrentVersionRun_504c {
  strings:
    $key_504c = { 03 23 [2] 27 2d [2] 0c 01 [2] 22 23 [2] 36 38 [2] 39 22 [2] 27 3f [2] 25 3e [2] 3e 38 [2] 22 3f [2] 3e 10 }

  condition:
    any of them
}