rule TTP_XOR_QUAD_CurrentVersionRun_9922 {
  strings:
    $key_9922 = { ca 4d [2] ee 43 [2] c5 6f [2] eb 4d [2] ff 56 [2] f0 4c [2] ee 51 [2] ec 50 [2] f7 56 [2] eb 51 [2] f7 7e }

  condition:
    any of them
}