rule TTP_XOR_QUAD_CurrentVersionRun_7a51 {
  strings:
    $key_7a51 = { 29 3e [2] 0d 30 [2] 26 1c [2] 08 3e [2] 1c 25 [2] 13 3f [2] 0d 22 [2] 0f 23 [2] 14 25 [2] 08 22 [2] 14 0d }

  condition:
    any of them
}