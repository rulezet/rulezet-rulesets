rule TTP_XOR_QUAD_CurrentVersionRun_9b70 {
  strings:
    $key_9b70 = { c8 1f [2] ec 11 [2] c7 3d [2] e9 1f [2] fd 04 [2] f2 1e [2] ec 03 [2] ee 02 [2] f5 04 [2] e9 03 [2] f5 2c }

  condition:
    any of them
}