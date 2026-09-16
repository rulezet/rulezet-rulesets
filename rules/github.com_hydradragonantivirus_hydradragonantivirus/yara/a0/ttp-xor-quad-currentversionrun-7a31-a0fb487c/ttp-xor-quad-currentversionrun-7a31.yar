rule TTP_XOR_QUAD_CurrentVersionRun_7a31 {
  strings:
    $key_7a31 = { 29 5e [2] 0d 50 [2] 26 7c [2] 08 5e [2] 1c 45 [2] 13 5f [2] 0d 42 [2] 0f 43 [2] 14 45 [2] 08 42 [2] 14 6d }

  condition:
    any of them
}