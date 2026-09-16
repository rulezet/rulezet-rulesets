rule TTP_XOR_QUAD_CurrentVersionRun_0651 {
  strings:
    $key_0651 = { 55 3e [2] 71 30 [2] 5a 1c [2] 74 3e [2] 60 25 [2] 6f 3f [2] 71 22 [2] 73 23 [2] 68 25 [2] 74 22 [2] 68 0d }

  condition:
    any of them
}