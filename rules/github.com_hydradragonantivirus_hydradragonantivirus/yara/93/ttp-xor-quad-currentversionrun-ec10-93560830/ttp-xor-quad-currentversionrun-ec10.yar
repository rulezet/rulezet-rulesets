rule TTP_XOR_QUAD_CurrentVersionRun_ec10 {
  strings:
    $key_ec10 = { bf 7f [2] 9b 71 [2] b0 5d [2] 9e 7f [2] 8a 64 [2] 85 7e [2] 9b 63 [2] 99 62 [2] 82 64 [2] 9e 63 [2] 82 4c }

  condition:
    any of them
}