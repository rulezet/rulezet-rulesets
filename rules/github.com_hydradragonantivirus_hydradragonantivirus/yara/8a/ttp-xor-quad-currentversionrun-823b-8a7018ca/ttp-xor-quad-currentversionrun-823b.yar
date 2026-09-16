rule TTP_XOR_QUAD_CurrentVersionRun_823b {
  strings:
    $key_823b = { d1 54 [2] f5 5a [2] de 76 [2] f0 54 [2] e4 4f [2] eb 55 [2] f5 48 [2] f7 49 [2] ec 4f [2] f0 48 [2] ec 67 }

  condition:
    any of them
}