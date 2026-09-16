rule TTP_XOR_QUAD_CurrentVersionRun_3fda {
  strings:
    $key_3fda = { 6c b5 [2] 48 bb [2] 63 97 [2] 4d b5 [2] 59 ae [2] 56 b4 [2] 48 a9 [2] 4a a8 [2] 51 ae [2] 4d a9 [2] 51 86 }

  condition:
    any of them
}