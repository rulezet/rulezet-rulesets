rule TTP_XOR_QUAD_CurrentVersionRun_6a4a {
  strings:
    $key_6a4a = { 39 25 [2] 1d 2b [2] 36 07 [2] 18 25 [2] 0c 3e [2] 03 24 [2] 1d 39 [2] 1f 38 [2] 04 3e [2] 18 39 [2] 04 16 }

  condition:
    any of them
}