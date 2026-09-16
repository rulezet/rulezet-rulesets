rule TTP_XOR_QUAD_CurrentVersionRun_1fd0 {
  strings:
    $key_1fd0 = { 4c bf [2] 68 b1 [2] 43 9d [2] 6d bf [2] 79 a4 [2] 76 be [2] 68 a3 [2] 6a a2 [2] 71 a4 [2] 6d a3 [2] 71 8c }

  condition:
    any of them
}