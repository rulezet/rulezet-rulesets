rule TTP_XOR_QUAD_CurrentVersionRun_0e41 {
  strings:
    $key_0e41 = { 5d 2e [2] 79 20 [2] 52 0c [2] 7c 2e [2] 68 35 [2] 67 2f [2] 79 32 [2] 7b 33 [2] 60 35 [2] 7c 32 [2] 60 1d }

  condition:
    any of them
}