rule TTP_XOR_QUAD_CurrentVersionRun_6bf1 {
  strings:
    $key_6bf1 = { 38 9e [2] 1c 90 [2] 37 bc [2] 19 9e [2] 0d 85 [2] 02 9f [2] 1c 82 [2] 1e 83 [2] 05 85 [2] 19 82 [2] 05 ad }

  condition:
    any of them
}