rule TTP_XOR_QUAD_CurrentVersionRun_dbbb {
  strings:
    $key_dbbb = { 88 d4 [2] ac da [2] 87 f6 [2] a9 d4 [2] bd cf [2] b2 d5 [2] ac c8 [2] ae c9 [2] b5 cf [2] a9 c8 [2] b5 e7 }

  condition:
    any of them
}