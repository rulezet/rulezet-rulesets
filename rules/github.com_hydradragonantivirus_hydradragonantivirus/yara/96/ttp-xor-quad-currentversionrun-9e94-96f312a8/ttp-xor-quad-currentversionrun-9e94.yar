rule TTP_XOR_QUAD_CurrentVersionRun_9e94 {
  strings:
    $key_9e94 = { cd fb [2] e9 f5 [2] c2 d9 [2] ec fb [2] f8 e0 [2] f7 fa [2] e9 e7 [2] eb e6 [2] f0 e0 [2] ec e7 [2] f0 c8 }

  condition:
    any of them
}