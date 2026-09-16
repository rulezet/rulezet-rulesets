rule TTP_XOR_QUAD_CurrentVersionRun_15bf {
  strings:
    $key_15bf = { 46 d0 [2] 62 de [2] 49 f2 [2] 67 d0 [2] 73 cb [2] 7c d1 [2] 62 cc [2] 60 cd [2] 7b cb [2] 67 cc [2] 7b e3 }

  condition:
    any of them
}