rule TTP_XOR_QUAD_CurrentVersionRun_2e71 {
  strings:
    $key_2e71 = { 7d 1e [2] 59 10 [2] 72 3c [2] 5c 1e [2] 48 05 [2] 47 1f [2] 59 02 [2] 5b 03 [2] 40 05 [2] 5c 02 [2] 40 2d }

  condition:
    any of them
}