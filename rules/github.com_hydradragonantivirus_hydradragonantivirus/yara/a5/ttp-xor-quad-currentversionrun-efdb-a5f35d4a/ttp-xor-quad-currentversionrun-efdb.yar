rule TTP_XOR_QUAD_CurrentVersionRun_efdb {
  strings:
    $key_efdb = { bc b4 [2] 98 ba [2] b3 96 [2] 9d b4 [2] 89 af [2] 86 b5 [2] 98 a8 [2] 9a a9 [2] 81 af [2] 9d a8 [2] 81 87 }

  condition:
    any of them
}