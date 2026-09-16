rule TTP_XOR_QUAD_CurrentVersionRun_1a21 {
  strings:
    $key_1a21 = { 49 4e [2] 6d 40 [2] 46 6c [2] 68 4e [2] 7c 55 [2] 73 4f [2] 6d 52 [2] 6f 53 [2] 74 55 [2] 68 52 [2] 74 7d }

  condition:
    any of them
}