rule TTP_XOR_QUAD_CurrentVersionRun_d1fd {
  strings:
    $key_d1fd = { 82 92 [2] a6 9c [2] 8d b0 [2] a3 92 [2] b7 89 [2] b8 93 [2] a6 8e [2] a4 8f [2] bf 89 [2] a3 8e [2] bf a1 }

  condition:
    any of them
}