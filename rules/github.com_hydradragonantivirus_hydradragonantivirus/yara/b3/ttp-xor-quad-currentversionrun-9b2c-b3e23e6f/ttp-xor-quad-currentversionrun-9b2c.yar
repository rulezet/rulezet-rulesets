rule TTP_XOR_QUAD_CurrentVersionRun_9b2c {
  strings:
    $key_9b2c = { c8 43 [2] ec 4d [2] c7 61 [2] e9 43 [2] fd 58 [2] f2 42 [2] ec 5f [2] ee 5e [2] f5 58 [2] e9 5f [2] f5 70 }

  condition:
    any of them
}