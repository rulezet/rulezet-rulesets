rule TTP_XOR_QUAD_CurrentVersionRun_ddcc {
  strings:
    $key_ddcc = { 8e a3 [2] aa ad [2] 81 81 [2] af a3 [2] bb b8 [2] b4 a2 [2] aa bf [2] a8 be [2] b3 b8 [2] af bf [2] b3 90 }

  condition:
    any of them
}