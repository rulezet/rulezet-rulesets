rule TTP_XOR_QUAD_CurrentVersionRun_5f12 {
  strings:
    $key_5f12 = { 0c 7d [2] 28 73 [2] 03 5f [2] 2d 7d [2] 39 66 [2] 36 7c [2] 28 61 [2] 2a 60 [2] 31 66 [2] 2d 61 [2] 31 4e }

  condition:
    any of them
}