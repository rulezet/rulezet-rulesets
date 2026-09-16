rule TTP_XOR_QUAD_CurrentVersionRun_8acc {
  strings:
    $key_8acc = { d9 a3 [2] fd ad [2] d6 81 [2] f8 a3 [2] ec b8 [2] e3 a2 [2] fd bf [2] ff be [2] e4 b8 [2] f8 bf [2] e4 90 }

  condition:
    any of them
}