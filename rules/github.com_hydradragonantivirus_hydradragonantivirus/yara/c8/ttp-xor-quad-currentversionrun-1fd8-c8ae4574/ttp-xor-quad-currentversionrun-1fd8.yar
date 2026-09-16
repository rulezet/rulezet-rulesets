rule TTP_XOR_QUAD_CurrentVersionRun_1fd8 {
  strings:
    $key_1fd8 = { 4c b7 [2] 68 b9 [2] 43 95 [2] 6d b7 [2] 79 ac [2] 76 b6 [2] 68 ab [2] 6a aa [2] 71 ac [2] 6d ab [2] 71 84 }

  condition:
    any of them
}