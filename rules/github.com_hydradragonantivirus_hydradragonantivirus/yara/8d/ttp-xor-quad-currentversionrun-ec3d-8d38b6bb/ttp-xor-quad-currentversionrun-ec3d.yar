rule TTP_XOR_QUAD_CurrentVersionRun_ec3d {
  strings:
    $key_ec3d = { bf 52 [2] 9b 5c [2] b0 70 [2] 9e 52 [2] 8a 49 [2] 85 53 [2] 9b 4e [2] 99 4f [2] 82 49 [2] 9e 4e [2] 82 61 }

  condition:
    any of them
}