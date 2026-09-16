rule TTP_XOR_QUAD_CurrentVersionRun_99fc {
  strings:
    $key_99fc = { ca 93 [2] ee 9d [2] c5 b1 [2] eb 93 [2] ff 88 [2] f0 92 [2] ee 8f [2] ec 8e [2] f7 88 [2] eb 8f [2] f7 a0 }

  condition:
    any of them
}