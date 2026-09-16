rule TTP_XOR_QUAD_CurrentVersionRun_9b3c {
  strings:
    $key_9b3c = { c8 53 [2] ec 5d [2] c7 71 [2] e9 53 [2] fd 48 [2] f2 52 [2] ec 4f [2] ee 4e [2] f5 48 [2] e9 4f [2] f5 60 }

  condition:
    any of them
}