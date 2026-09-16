rule TTP_XOR_QUAD_CurrentVersionRun_823c {
  strings:
    $key_823c = { d1 53 [2] f5 5d [2] de 71 [2] f0 53 [2] e4 48 [2] eb 52 [2] f5 4f [2] f7 4e [2] ec 48 [2] f0 4f [2] ec 60 }

  condition:
    any of them
}