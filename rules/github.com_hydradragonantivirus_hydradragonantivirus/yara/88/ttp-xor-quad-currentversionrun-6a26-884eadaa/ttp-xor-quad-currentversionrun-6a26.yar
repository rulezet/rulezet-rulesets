rule TTP_XOR_QUAD_CurrentVersionRun_6a26 {
  strings:
    $key_6a26 = { 39 49 [2] 1d 47 [2] 36 6b [2] 18 49 [2] 0c 52 [2] 03 48 [2] 1d 55 [2] 1f 54 [2] 04 52 [2] 18 55 [2] 04 7a }

  condition:
    any of them
}