rule TTP_XOR_QUAD_CurrentVersionRun_993f {
  strings:
    $key_993f = { ca 50 [2] ee 5e [2] c5 72 [2] eb 50 [2] ff 4b [2] f0 51 [2] ee 4c [2] ec 4d [2] f7 4b [2] eb 4c [2] f7 63 }

  condition:
    any of them
}