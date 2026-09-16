rule TTP_XOR_QUAD_CurrentVersionRun_1fd5 {
  strings:
    $key_1fd5 = { 4c ba [2] 68 b4 [2] 43 98 [2] 6d ba [2] 79 a1 [2] 76 bb [2] 68 a6 [2] 6a a7 [2] 71 a1 [2] 6d a6 [2] 71 89 }

  condition:
    any of them
}