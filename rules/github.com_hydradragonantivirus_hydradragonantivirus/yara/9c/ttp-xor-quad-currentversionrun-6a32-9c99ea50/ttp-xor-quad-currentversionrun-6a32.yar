rule TTP_XOR_QUAD_CurrentVersionRun_6a32 {
  strings:
    $key_6a32 = { 39 5d [2] 1d 53 [2] 36 7f [2] 18 5d [2] 0c 46 [2] 03 5c [2] 1d 41 [2] 1f 40 [2] 04 46 [2] 18 41 [2] 04 6e }

  condition:
    any of them
}