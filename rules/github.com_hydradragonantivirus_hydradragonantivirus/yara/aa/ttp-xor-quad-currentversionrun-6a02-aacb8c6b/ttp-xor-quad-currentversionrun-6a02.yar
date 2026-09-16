rule TTP_XOR_QUAD_CurrentVersionRun_6a02 {
  strings:
    $key_6a02 = { 39 6d [2] 1d 63 [2] 36 4f [2] 18 6d [2] 0c 76 [2] 03 6c [2] 1d 71 [2] 1f 70 [2] 04 76 [2] 18 71 [2] 04 5e }

  condition:
    any of them
}