rule TTP_XOR_QUAD_CurrentVersionRun_ec70 {
  strings:
    $key_ec70 = { bf 1f [2] 9b 11 [2] b0 3d [2] 9e 1f [2] 8a 04 [2] 85 1e [2] 9b 03 [2] 99 02 [2] 82 04 [2] 9e 03 [2] 82 2c }

  condition:
    any of them
}