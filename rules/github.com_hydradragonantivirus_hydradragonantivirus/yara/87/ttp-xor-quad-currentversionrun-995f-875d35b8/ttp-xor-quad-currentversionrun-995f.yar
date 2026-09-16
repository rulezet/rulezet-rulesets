rule TTP_XOR_QUAD_CurrentVersionRun_995f {
  strings:
    $key_995f = { ca 30 [2] ee 3e [2] c5 12 [2] eb 30 [2] ff 2b [2] f0 31 [2] ee 2c [2] ec 2d [2] f7 2b [2] eb 2c [2] f7 03 }

  condition:
    any of them
}