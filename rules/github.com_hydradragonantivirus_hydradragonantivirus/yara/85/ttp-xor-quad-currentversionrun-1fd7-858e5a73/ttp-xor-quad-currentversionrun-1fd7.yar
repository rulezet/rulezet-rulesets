rule TTP_XOR_QUAD_CurrentVersionRun_1fd7 {
  strings:
    $key_1fd7 = { 4c b8 [2] 68 b6 [2] 43 9a [2] 6d b8 [2] 79 a3 [2] 76 b9 [2] 68 a4 [2] 6a a5 [2] 71 a3 [2] 6d a4 [2] 71 8b }

  condition:
    any of them
}