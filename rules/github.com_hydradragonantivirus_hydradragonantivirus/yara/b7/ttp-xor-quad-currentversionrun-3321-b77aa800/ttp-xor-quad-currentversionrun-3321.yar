rule TTP_XOR_QUAD_CurrentVersionRun_3321 {
  strings:
    $key_3321 = { 60 4e [2] 44 40 [2] 6f 6c [2] 41 4e [2] 55 55 [2] 5a 4f [2] 44 52 [2] 46 53 [2] 5d 55 [2] 41 52 [2] 5d 7d }

  condition:
    any of them
}