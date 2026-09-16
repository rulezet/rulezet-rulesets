rule TTP_XOR_QUAD_CurrentVersionRun_4b33 {
  strings:
    $key_4b33 = { 18 5c [2] 3c 52 [2] 17 7e [2] 39 5c [2] 2d 47 [2] 22 5d [2] 3c 40 [2] 3e 41 [2] 25 47 [2] 39 40 [2] 25 6f }

  condition:
    any of them
}