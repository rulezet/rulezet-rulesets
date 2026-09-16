rule TTP_XOR_QUAD_CurrentVersionRun_db9a {
  strings:
    $key_db9a = { 88 f5 [2] ac fb [2] 87 d7 [2] a9 f5 [2] bd ee [2] b2 f4 [2] ac e9 [2] ae e8 [2] b5 ee [2] a9 e9 [2] b5 c6 }

  condition:
    any of them
}