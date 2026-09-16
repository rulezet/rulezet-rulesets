rule TTP_XOR_QUAD_CurrentVersionRun_3f71 {
  strings:
    $key_3f71 = { 6c 1e [2] 48 10 [2] 63 3c [2] 4d 1e [2] 59 05 [2] 56 1f [2] 48 02 [2] 4a 03 [2] 51 05 [2] 4d 02 [2] 51 2d }

  condition:
    any of them
}