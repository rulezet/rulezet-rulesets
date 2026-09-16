rule TTP_XOR_QUAD_CurrentVersionRun_9be1 {
  strings:
    $key_9be1 = { c8 8e [2] ec 80 [2] c7 ac [2] e9 8e [2] fd 95 [2] f2 8f [2] ec 92 [2] ee 93 [2] f5 95 [2] e9 92 [2] f5 bd }

  condition:
    any of them
}