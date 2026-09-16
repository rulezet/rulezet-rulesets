rule TTP_XOR_QUAD_CurrentVersionRun_7a21 {
  strings:
    $key_7a21 = { 29 4e [2] 0d 40 [2] 26 6c [2] 08 4e [2] 1c 55 [2] 13 4f [2] 0d 52 [2] 0f 53 [2] 14 55 [2] 08 52 [2] 14 7d }

  condition:
    any of them
}