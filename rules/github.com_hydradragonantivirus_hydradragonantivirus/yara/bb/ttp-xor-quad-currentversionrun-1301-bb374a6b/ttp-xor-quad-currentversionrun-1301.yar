rule TTP_XOR_QUAD_CurrentVersionRun_1301 {
  strings:
    $key_1301 = { 40 6e [2] 64 60 [2] 4f 4c [2] 61 6e [2] 75 75 [2] 7a 6f [2] 64 72 [2] 66 73 [2] 7d 75 [2] 61 72 [2] 7d 5d }

  condition:
    any of them
}