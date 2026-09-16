rule TTP_XOR_QUAD_CurrentVersionRun_9beb {
  strings:
    $key_9beb = { c8 84 [2] ec 8a [2] c7 a6 [2] e9 84 [2] fd 9f [2] f2 85 [2] ec 98 [2] ee 99 [2] f5 9f [2] e9 98 [2] f5 b7 }

  condition:
    any of them
}