rule TTP_XOR_QUAD_CurrentVersionRun_4b0c {
  strings:
    $key_4b0c = { 18 63 [2] 3c 6d [2] 17 41 [2] 39 63 [2] 2d 78 [2] 22 62 [2] 3c 7f [2] 3e 7e [2] 25 78 [2] 39 7f [2] 25 50 }

  condition:
    any of them
}