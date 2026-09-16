rule TTP_XOR_QUAD_CurrentVersionRun_dbca {
  strings:
    $key_dbca = { 88 a5 [2] ac ab [2] 87 87 [2] a9 a5 [2] bd be [2] b2 a4 [2] ac b9 [2] ae b8 [2] b5 be [2] a9 b9 [2] b5 96 }

  condition:
    any of them
}