rule TTP_XOR_QUAD_CurrentVersionRun_2d21 {
  strings:
    $key_2d21 = { 7e 4e [2] 5a 40 [2] 71 6c [2] 5f 4e [2] 4b 55 [2] 44 4f [2] 5a 52 [2] 58 53 [2] 43 55 [2] 5f 52 [2] 43 7d }

  condition:
    any of them
}