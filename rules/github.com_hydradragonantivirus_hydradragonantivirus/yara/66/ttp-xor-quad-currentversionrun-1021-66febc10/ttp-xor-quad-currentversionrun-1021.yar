rule TTP_XOR_QUAD_CurrentVersionRun_1021 {
  strings:
    $key_1021 = { 43 4e [2] 67 40 [2] 4c 6c [2] 62 4e [2] 76 55 [2] 79 4f [2] 67 52 [2] 65 53 [2] 7e 55 [2] 62 52 [2] 7e 7d }

  condition:
    any of them
}