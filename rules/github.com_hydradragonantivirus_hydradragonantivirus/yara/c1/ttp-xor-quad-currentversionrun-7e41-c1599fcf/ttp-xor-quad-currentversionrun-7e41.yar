rule TTP_XOR_QUAD_CurrentVersionRun_7e41 {
  strings:
    $key_7e41 = { 2d 2e [2] 09 20 [2] 22 0c [2] 0c 2e [2] 18 35 [2] 17 2f [2] 09 32 [2] 0b 33 [2] 10 35 [2] 0c 32 [2] 10 1d }

  condition:
    any of them
}