rule TTP_XOR_QUAD_CurrentVersionRun_2311 {
  strings:
    $key_2311 = { 70 7e [2] 54 70 [2] 7f 5c [2] 51 7e [2] 45 65 [2] 4a 7f [2] 54 62 [2] 56 63 [2] 4d 65 [2] 51 62 [2] 4d 4d }

  condition:
    any of them
}