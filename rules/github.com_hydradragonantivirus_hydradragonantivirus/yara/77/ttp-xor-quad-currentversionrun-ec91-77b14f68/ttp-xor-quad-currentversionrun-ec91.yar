rule TTP_XOR_QUAD_CurrentVersionRun_ec91 {
  strings:
    $key_ec91 = { bf fe [2] 9b f0 [2] b0 dc [2] 9e fe [2] 8a e5 [2] 85 ff [2] 9b e2 [2] 99 e3 [2] 82 e5 [2] 9e e2 [2] 82 cd }

  condition:
    any of them
}