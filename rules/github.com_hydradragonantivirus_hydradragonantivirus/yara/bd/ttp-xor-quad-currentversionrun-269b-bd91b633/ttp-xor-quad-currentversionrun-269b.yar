rule TTP_XOR_QUAD_CurrentVersionRun_269b {
  strings:
    $key_269b = { 75 f4 [2] 51 fa [2] 7a d6 [2] 54 f4 [2] 40 ef [2] 4f f5 [2] 51 e8 [2] 53 e9 [2] 48 ef [2] 54 e8 [2] 48 c7 }

  condition:
    any of them
}