rule TTP_XOR_QUAD_CurrentVersionRun_6a01 {
  strings:
    $key_6a01 = { 39 6e [2] 1d 60 [2] 36 4c [2] 18 6e [2] 0c 75 [2] 03 6f [2] 1d 72 [2] 1f 73 [2] 04 75 [2] 18 72 [2] 04 5d }

  condition:
    any of them
}