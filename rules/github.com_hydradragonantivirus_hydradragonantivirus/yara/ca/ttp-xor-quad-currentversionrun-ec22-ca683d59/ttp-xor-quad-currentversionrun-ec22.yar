rule TTP_XOR_QUAD_CurrentVersionRun_ec22 {
  strings:
    $key_ec22 = { bf 4d [2] 9b 43 [2] b0 6f [2] 9e 4d [2] 8a 56 [2] 85 4c [2] 9b 51 [2] 99 50 [2] 82 56 [2] 9e 51 [2] 82 7e }

  condition:
    any of them
}