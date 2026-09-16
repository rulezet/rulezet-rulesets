rule TTP_XOR_QUAD_CurrentVersionRun_8214 {
  strings:
    $key_8214 = { d1 7b [2] f5 75 [2] de 59 [2] f0 7b [2] e4 60 [2] eb 7a [2] f5 67 [2] f7 66 [2] ec 60 [2] f0 67 [2] ec 48 }

  condition:
    any of them
}