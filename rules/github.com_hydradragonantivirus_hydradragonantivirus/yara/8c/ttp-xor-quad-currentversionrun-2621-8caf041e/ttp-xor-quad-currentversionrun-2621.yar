rule TTP_XOR_QUAD_CurrentVersionRun_2621 {
  strings:
    $key_2621 = { 75 4e [2] 51 40 [2] 7a 6c [2] 54 4e [2] 40 55 [2] 4f 4f [2] 51 52 [2] 53 53 [2] 48 55 [2] 54 52 [2] 48 7d }

  condition:
    any of them
}