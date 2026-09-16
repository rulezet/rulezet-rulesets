rule TTP_XOR_QUAD_CurrentVersionRun_3a41 {
  strings:
    $key_3a41 = { 69 2e [2] 4d 20 [2] 66 0c [2] 48 2e [2] 5c 35 [2] 53 2f [2] 4d 32 [2] 4f 33 [2] 54 35 [2] 48 32 [2] 54 1d }

  condition:
    any of them
}