rule TTP_XOR_QUAD_CurrentVersionRun_6af1 {
  strings:
    $key_6af1 = { 39 9e [2] 1d 90 [2] 36 bc [2] 18 9e [2] 0c 85 [2] 03 9f [2] 1d 82 [2] 1f 83 [2] 04 85 [2] 18 82 [2] 04 ad }

  condition:
    any of them
}