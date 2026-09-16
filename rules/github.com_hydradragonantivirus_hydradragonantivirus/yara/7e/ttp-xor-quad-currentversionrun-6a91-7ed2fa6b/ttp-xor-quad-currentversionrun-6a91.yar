rule TTP_XOR_QUAD_CurrentVersionRun_6a91 {
  strings:
    $key_6a91 = { 39 fe [2] 1d f0 [2] 36 dc [2] 18 fe [2] 0c e5 [2] 03 ff [2] 1d e2 [2] 1f e3 [2] 04 e5 [2] 18 e2 [2] 04 cd }

  condition:
    any of them
}