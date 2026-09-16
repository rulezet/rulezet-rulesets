rule TTP_XOR_QUAD_CurrentVersionRun_0a01 {
  strings:
    $key_0a01 = { 59 6e [2] 7d 60 [2] 56 4c [2] 78 6e [2] 6c 75 [2] 63 6f [2] 7d 72 [2] 7f 73 [2] 64 75 [2] 78 72 [2] 64 5d }

  condition:
    any of them
}