rule TTP_XOR_QUAD_CurrentVersionRun_d588 {
  strings:
    $key_d588 = { 86 e7 [2] a2 e9 [2] 89 c5 [2] a7 e7 [2] b3 fc [2] bc e6 [2] a2 fb [2] a0 fa [2] bb fc [2] a7 fb [2] bb d4 }

  condition:
    any of them
}