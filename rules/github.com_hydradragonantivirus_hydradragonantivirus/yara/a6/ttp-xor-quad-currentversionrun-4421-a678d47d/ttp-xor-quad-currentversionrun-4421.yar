rule TTP_XOR_QUAD_CurrentVersionRun_4421 {
  strings:
    $key_4421 = { 17 4e [2] 33 40 [2] 18 6c [2] 36 4e [2] 22 55 [2] 2d 4f [2] 33 52 [2] 31 53 [2] 2a 55 [2] 36 52 [2] 2a 7d }

  condition:
    any of them
}