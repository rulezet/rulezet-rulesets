rule TTP_XOR_QUAD_CurrentVersionRun_0671 {
  strings:
    $key_0671 = { 55 1e [2] 71 10 [2] 5a 3c [2] 74 1e [2] 60 05 [2] 6f 1f [2] 71 02 [2] 73 03 [2] 68 05 [2] 74 02 [2] 68 2d }

  condition:
    any of them
}