rule TTP_XOR_QUAD_CurrentVersionRun_3b11 {
  strings:
    $key_3b11 = { 68 7e [2] 4c 70 [2] 67 5c [2] 49 7e [2] 5d 65 [2] 52 7f [2] 4c 62 [2] 4e 63 [2] 55 65 [2] 49 62 [2] 55 4d }

  condition:
    any of them
}