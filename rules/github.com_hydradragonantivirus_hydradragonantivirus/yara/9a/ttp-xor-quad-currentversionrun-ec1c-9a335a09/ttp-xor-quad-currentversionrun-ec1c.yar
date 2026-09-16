rule TTP_XOR_QUAD_CurrentVersionRun_ec1c {
  strings:
    $key_ec1c = { bf 73 [2] 9b 7d [2] b0 51 [2] 9e 73 [2] 8a 68 [2] 85 72 [2] 9b 6f [2] 99 6e [2] 82 68 [2] 9e 6f [2] 82 40 }

  condition:
    any of them
}