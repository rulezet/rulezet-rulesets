rule TTP_XOR_QUAD_CurrentVersionRun_9b00 {
  strings:
    $key_9b00 = { c8 6f [2] ec 61 [2] c7 4d [2] e9 6f [2] fd 74 [2] f2 6e [2] ec 73 [2] ee 72 [2] f5 74 [2] e9 73 [2] f5 5c }

  condition:
    any of them
}