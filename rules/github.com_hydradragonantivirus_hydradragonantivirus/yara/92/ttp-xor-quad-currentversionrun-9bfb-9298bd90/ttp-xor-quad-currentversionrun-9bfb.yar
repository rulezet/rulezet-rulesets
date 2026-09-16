rule TTP_XOR_QUAD_CurrentVersionRun_9bfb {
  strings:
    $key_9bfb = { c8 94 [2] ec 9a [2] c7 b6 [2] e9 94 [2] fd 8f [2] f2 95 [2] ec 88 [2] ee 89 [2] f5 8f [2] e9 88 [2] f5 a7 }

  condition:
    any of them
}