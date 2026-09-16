rule TTP_XOR_QUAD_CurrentVersionRun_41bf {
  strings:
    $key_41bf = { 12 d0 [2] 36 de [2] 1d f2 [2] 33 d0 [2] 27 cb [2] 28 d1 [2] 36 cc [2] 34 cd [2] 2f cb [2] 33 cc [2] 2f e3 }

  condition:
    any of them
}