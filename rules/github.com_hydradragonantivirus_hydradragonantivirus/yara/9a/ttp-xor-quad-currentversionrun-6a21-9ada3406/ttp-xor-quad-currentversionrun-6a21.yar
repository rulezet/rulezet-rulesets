rule TTP_XOR_QUAD_CurrentVersionRun_6a21 {
  strings:
    $key_6a21 = { 39 4e [2] 1d 40 [2] 36 6c [2] 18 4e [2] 0c 55 [2] 03 4f [2] 1d 52 [2] 1f 53 [2] 04 55 [2] 18 52 [2] 04 7d }

  condition:
    any of them
}