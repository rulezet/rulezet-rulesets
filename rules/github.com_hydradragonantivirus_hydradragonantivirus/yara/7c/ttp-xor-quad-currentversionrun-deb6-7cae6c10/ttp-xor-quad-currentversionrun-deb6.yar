rule TTP_XOR_QUAD_CurrentVersionRun_deb6 {
  strings:
    $key_deb6 = { 8d d9 [2] a9 d7 [2] 82 fb [2] ac d9 [2] b8 c2 [2] b7 d8 [2] a9 c5 [2] ab c4 [2] b0 c2 [2] ac c5 [2] b0 ea }

  condition:
    any of them
}