rule TTP_XOR_QUAD_CurrentVersionRun_1601 {
  strings:
    $key_1601 = { 45 6e [2] 61 60 [2] 4a 4c [2] 64 6e [2] 70 75 [2] 7f 6f [2] 61 72 [2] 63 73 [2] 78 75 [2] 64 72 [2] 78 5d }

  condition:
    any of them
}