rule TTP_XOR_QUAD_CurrentVersionRun_1d21 {
  strings:
    $key_1d21 = { 4e 4e [2] 6a 40 [2] 41 6c [2] 6f 4e [2] 7b 55 [2] 74 4f [2] 6a 52 [2] 68 53 [2] 73 55 [2] 6f 52 [2] 73 7d }

  condition:
    any of them
}