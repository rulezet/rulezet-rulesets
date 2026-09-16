rule TTP_XOR_QUAD_CurrentVersionRun_6a0c {
  strings:
    $key_6a0c = { 39 63 [2] 1d 6d [2] 36 41 [2] 18 63 [2] 0c 78 [2] 03 62 [2] 1d 7f [2] 1f 7e [2] 04 78 [2] 18 7f [2] 04 50 }

  condition:
    any of them
}