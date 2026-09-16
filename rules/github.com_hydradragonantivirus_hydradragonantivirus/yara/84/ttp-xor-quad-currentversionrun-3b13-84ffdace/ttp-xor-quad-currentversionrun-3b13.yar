rule TTP_XOR_QUAD_CurrentVersionRun_3b13 {
  strings:
    $key_3b13 = { 68 7c [2] 4c 72 [2] 67 5e [2] 49 7c [2] 5d 67 [2] 52 7d [2] 4c 60 [2] 4e 61 [2] 55 67 [2] 49 60 [2] 55 4f }

  condition:
    any of them
}