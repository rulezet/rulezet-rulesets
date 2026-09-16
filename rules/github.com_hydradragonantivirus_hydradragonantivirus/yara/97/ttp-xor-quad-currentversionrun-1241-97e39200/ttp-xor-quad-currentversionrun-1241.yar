rule TTP_XOR_QUAD_CurrentVersionRun_1241 {
  strings:
    $key_1241 = { 41 2e [2] 65 20 [2] 4e 0c [2] 60 2e [2] 74 35 [2] 7b 2f [2] 65 32 [2] 67 33 [2] 7c 35 [2] 60 32 [2] 7c 1d }

  condition:
    any of them
}