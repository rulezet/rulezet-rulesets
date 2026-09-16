rule TTP_XOR_QUAD_CurrentVersionRun_8dcc {
  strings:
    $key_8dcc = { de a3 [2] fa ad [2] d1 81 [2] ff a3 [2] eb b8 [2] e4 a2 [2] fa bf [2] f8 be [2] e3 b8 [2] ff bf [2] e3 90 }

  condition:
    any of them
}