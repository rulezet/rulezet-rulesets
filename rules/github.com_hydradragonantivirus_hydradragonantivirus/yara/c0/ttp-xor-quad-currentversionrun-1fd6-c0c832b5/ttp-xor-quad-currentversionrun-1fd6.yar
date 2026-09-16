rule TTP_XOR_QUAD_CurrentVersionRun_1fd6 {
  strings:
    $key_1fd6 = { 4c b9 [2] 68 b7 [2] 43 9b [2] 6d b9 [2] 79 a2 [2] 76 b8 [2] 68 a5 [2] 6a a4 [2] 71 a2 [2] 6d a5 [2] 71 8a }

  condition:
    any of them
}