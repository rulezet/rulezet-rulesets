rule TTP_XOR_QUAD_CurrentVersionRun_0f71 {
  strings:
    $key_0f71 = { 5c 1e [2] 78 10 [2] 53 3c [2] 7d 1e [2] 69 05 [2] 66 1f [2] 78 02 [2] 7a 03 [2] 61 05 [2] 7d 02 [2] 61 2d }

  condition:
    any of them
}