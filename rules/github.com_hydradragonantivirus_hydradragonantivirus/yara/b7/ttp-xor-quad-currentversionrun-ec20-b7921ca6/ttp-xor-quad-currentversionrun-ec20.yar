rule TTP_XOR_QUAD_CurrentVersionRun_ec20 {
  strings:
    $key_ec20 = { bf 4f [2] 9b 41 [2] b0 6d [2] 9e 4f [2] 8a 54 [2] 85 4e [2] 9b 53 [2] 99 52 [2] 82 54 [2] 9e 53 [2] 82 7c }

  condition:
    any of them
}