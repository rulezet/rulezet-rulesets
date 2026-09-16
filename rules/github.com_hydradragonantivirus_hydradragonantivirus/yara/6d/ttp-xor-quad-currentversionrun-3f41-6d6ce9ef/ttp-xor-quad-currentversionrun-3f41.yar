rule TTP_XOR_QUAD_CurrentVersionRun_3f41 {
  strings:
    $key_3f41 = { 6c 2e [2] 48 20 [2] 63 0c [2] 4d 2e [2] 59 35 [2] 56 2f [2] 48 32 [2] 4a 33 [2] 51 35 [2] 4d 32 [2] 51 1d }

  condition:
    any of them
}