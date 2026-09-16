rule TTP_XOR_QUAD_CurrentVersionRun_cf27 {
  strings:
    $key_cf27 = { 9c 48 [2] b8 46 [2] 93 6a [2] bd 48 [2] a9 53 [2] a6 49 [2] b8 54 [2] ba 55 [2] a1 53 [2] bd 54 [2] a1 7b }

  condition:
    any of them
}