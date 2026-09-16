rule TTP_XOR_QUAD_CurrentVersionRun_4b13 {
  strings:
    $key_4b13 = { 18 7c [2] 3c 72 [2] 17 5e [2] 39 7c [2] 2d 67 [2] 22 7d [2] 3c 60 [2] 3e 61 [2] 25 67 [2] 39 60 [2] 25 4f }

  condition:
    any of them
}