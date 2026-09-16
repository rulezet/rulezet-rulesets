rule TTP_XOR_QUAD_CurrentVersionRun_1fd1 {
  strings:
    $key_1fd1 = { 4c be [2] 68 b0 [2] 43 9c [2] 6d be [2] 79 a5 [2] 76 bf [2] 68 a2 [2] 6a a3 [2] 71 a5 [2] 6d a2 [2] 71 8d }

  condition:
    any of them
}