rule TTP_XOR_QUAD_CurrentVersionRun_3e01 {
  strings:
    $key_3e01 = { 6d 6e [2] 49 60 [2] 62 4c [2] 4c 6e [2] 58 75 [2] 57 6f [2] 49 72 [2] 4b 73 [2] 50 75 [2] 4c 72 [2] 50 5d }

  condition:
    any of them
}