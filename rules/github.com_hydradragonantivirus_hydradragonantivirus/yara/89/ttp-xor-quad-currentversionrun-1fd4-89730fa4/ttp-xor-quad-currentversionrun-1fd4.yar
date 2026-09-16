rule TTP_XOR_QUAD_CurrentVersionRun_1fd4 {
  strings:
    $key_1fd4 = { 4c bb [2] 68 b5 [2] 43 99 [2] 6d bb [2] 79 a0 [2] 76 ba [2] 68 a7 [2] 6a a6 [2] 71 a0 [2] 6d a7 [2] 71 88 }

  condition:
    any of them
}