rule TTP_XOR_QUAD_CurrentVersionRun_9088 {
  strings:
    $key_9088 = { c3 e7 [2] e7 e9 [2] cc c5 [2] e2 e7 [2] f6 fc [2] f9 e6 [2] e7 fb [2] e5 fa [2] fe fc [2] e2 fb [2] fe d4 }

  condition:
    any of them
}