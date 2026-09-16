rule TTP_XOR_QUAD_CurrentVersionRun_3411 {
  strings:
    $key_3411 = { 67 7e [2] 43 70 [2] 68 5c [2] 46 7e [2] 52 65 [2] 5d 7f [2] 43 62 [2] 41 63 [2] 5a 65 [2] 46 62 [2] 5a 4d }

  condition:
    any of them
}