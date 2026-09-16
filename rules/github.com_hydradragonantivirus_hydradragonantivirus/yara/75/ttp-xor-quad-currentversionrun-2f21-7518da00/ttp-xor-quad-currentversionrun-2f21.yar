rule TTP_XOR_QUAD_CurrentVersionRun_2f21 {
  strings:
    $key_2f21 = { 7c 4e [2] 58 40 [2] 73 6c [2] 5d 4e [2] 49 55 [2] 46 4f [2] 58 52 [2] 5a 53 [2] 41 55 [2] 5d 52 [2] 41 7d }

  condition:
    any of them
}