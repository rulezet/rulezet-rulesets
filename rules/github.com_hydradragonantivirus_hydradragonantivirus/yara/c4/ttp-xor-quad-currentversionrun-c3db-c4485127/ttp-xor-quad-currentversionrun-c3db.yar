rule TTP_XOR_QUAD_CurrentVersionRun_c3db {
  strings:
    $key_c3db = { 90 b4 [2] b4 ba [2] 9f 96 [2] b1 b4 [2] a5 af [2] aa b5 [2] b4 a8 [2] b6 a9 [2] ad af [2] b1 a8 [2] ad 87 }

  condition:
    any of them
}