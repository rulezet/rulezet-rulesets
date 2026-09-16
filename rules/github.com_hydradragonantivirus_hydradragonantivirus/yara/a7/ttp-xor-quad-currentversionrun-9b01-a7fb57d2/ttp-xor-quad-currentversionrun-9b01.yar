rule TTP_XOR_QUAD_CurrentVersionRun_9b01 {
  strings:
    $key_9b01 = { c8 6e [2] ec 60 [2] c7 4c [2] e9 6e [2] fd 75 [2] f2 6f [2] ec 72 [2] ee 73 [2] f5 75 [2] e9 72 [2] f5 5d }

  condition:
    any of them
}