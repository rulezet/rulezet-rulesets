rule TTP_XOR_QUAD_CurrentVersionRun_6eda {
  strings:
    $key_6eda = { 3d b5 [2] 19 bb [2] 32 97 [2] 1c b5 [2] 08 ae [2] 07 b4 [2] 19 a9 [2] 1b a8 [2] 00 ae [2] 1c a9 [2] 00 86 }

  condition:
    any of them
}