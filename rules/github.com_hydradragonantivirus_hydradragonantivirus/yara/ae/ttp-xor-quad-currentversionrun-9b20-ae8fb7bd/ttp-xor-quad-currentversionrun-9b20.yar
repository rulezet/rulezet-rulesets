rule TTP_XOR_QUAD_CurrentVersionRun_9b20 {
  strings:
    $key_9b20 = { c8 4f [2] ec 41 [2] c7 6d [2] e9 4f [2] fd 54 [2] f2 4e [2] ec 53 [2] ee 52 [2] f5 54 [2] e9 53 [2] f5 7c }

  condition:
    any of them
}