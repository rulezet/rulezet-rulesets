rule TTP_XOR_QUAD_CurrentVersionRun_0301 {
  strings:
    $key_0301 = { 50 6e [2] 74 60 [2] 5f 4c [2] 71 6e [2] 65 75 [2] 6a 6f [2] 74 72 [2] 76 73 [2] 6d 75 [2] 71 72 [2] 6d 5d }

  condition:
    any of them
}