rule TTP_XOR_QUAD_CurrentVersionRun_9188 {
  strings:
    $key_9188 = { c2 e7 [2] e6 e9 [2] cd c5 [2] e3 e7 [2] f7 fc [2] f8 e6 [2] e6 fb [2] e4 fa [2] ff fc [2] e3 fb [2] ff d4 }

  condition:
    any of them
}