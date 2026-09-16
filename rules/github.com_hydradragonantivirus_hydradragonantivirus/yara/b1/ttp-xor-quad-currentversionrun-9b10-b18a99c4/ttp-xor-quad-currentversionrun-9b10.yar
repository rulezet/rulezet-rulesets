rule TTP_XOR_QUAD_CurrentVersionRun_9b10 {
  strings:
    $key_9b10 = { c8 7f [2] ec 71 [2] c7 5d [2] e9 7f [2] fd 64 [2] f2 7e [2] ec 63 [2] ee 62 [2] f5 64 [2] e9 63 [2] f5 4c }

  condition:
    any of them
}