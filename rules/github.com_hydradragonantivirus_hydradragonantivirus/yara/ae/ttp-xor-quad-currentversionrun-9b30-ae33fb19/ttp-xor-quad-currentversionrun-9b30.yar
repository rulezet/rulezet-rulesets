rule TTP_XOR_QUAD_CurrentVersionRun_9b30 {
  strings:
    $key_9b30 = { c8 5f [2] ec 51 [2] c7 7d [2] e9 5f [2] fd 44 [2] f2 5e [2] ec 43 [2] ee 42 [2] f5 44 [2] e9 43 [2] f5 6c }

  condition:
    any of them
}