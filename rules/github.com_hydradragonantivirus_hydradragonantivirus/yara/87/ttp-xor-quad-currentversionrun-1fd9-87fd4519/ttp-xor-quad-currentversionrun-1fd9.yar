rule TTP_XOR_QUAD_CurrentVersionRun_1fd9 {
  strings:
    $key_1fd9 = { 4c b6 [2] 68 b8 [2] 43 94 [2] 6d b6 [2] 79 ad [2] 76 b7 [2] 68 aa [2] 6a ab [2] 71 ad [2] 6d aa [2] 71 85 }

  condition:
    any of them
}