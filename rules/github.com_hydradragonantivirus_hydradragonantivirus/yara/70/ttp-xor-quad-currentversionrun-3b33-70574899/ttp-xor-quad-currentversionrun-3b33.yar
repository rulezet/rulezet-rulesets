rule TTP_XOR_QUAD_CurrentVersionRun_3b33 {
  strings:
    $key_3b33 = { 68 5c [2] 4c 52 [2] 67 7e [2] 49 5c [2] 5d 47 [2] 52 5d [2] 4c 40 [2] 4e 41 [2] 55 47 [2] 49 40 [2] 55 6f }

  condition:
    any of them
}