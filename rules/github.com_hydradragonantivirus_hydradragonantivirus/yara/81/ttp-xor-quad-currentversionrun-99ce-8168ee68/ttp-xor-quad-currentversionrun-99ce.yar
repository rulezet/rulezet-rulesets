rule TTP_XOR_QUAD_CurrentVersionRun_99ce {
  strings:
    $key_99ce = { ca a1 [2] ee af [2] c5 83 [2] eb a1 [2] ff ba [2] f0 a0 [2] ee bd [2] ec bc [2] f7 ba [2] eb bd [2] f7 92 }

  condition:
    any of them
}