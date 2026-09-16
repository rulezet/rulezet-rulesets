rule TTP_XOR_QUAD_CurrentVersionRun_d088 {
  strings:
    $key_d088 = { 83 e7 [2] a7 e9 [2] 8c c5 [2] a2 e7 [2] b6 fc [2] b9 e6 [2] a7 fb [2] a5 fa [2] be fc [2] a2 fb [2] be d4 }

  condition:
    any of them
}