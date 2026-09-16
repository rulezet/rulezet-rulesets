rule TTP_XOR_QUAD_CurrentVersionRun_4a91 {
  strings:
    $key_4a91 = { 19 fe [2] 3d f0 [2] 16 dc [2] 38 fe [2] 2c e5 [2] 23 ff [2] 3d e2 [2] 3f e3 [2] 24 e5 [2] 38 e2 [2] 24 cd }

  condition:
    any of them
}