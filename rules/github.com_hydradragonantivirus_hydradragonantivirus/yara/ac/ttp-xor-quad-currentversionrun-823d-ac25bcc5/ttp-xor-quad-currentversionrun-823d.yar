rule TTP_XOR_QUAD_CurrentVersionRun_823d {
  strings:
    $key_823d = { d1 52 [2] f5 5c [2] de 70 [2] f0 52 [2] e4 49 [2] eb 53 [2] f5 4e [2] f7 4f [2] ec 49 [2] f0 4e [2] ec 61 }

  condition:
    any of them
}