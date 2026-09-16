rule TTP_XOR_QUAD_CurrentVersionRun_9bee {
  strings:
    $key_9bee = { c8 81 [2] ec 8f [2] c7 a3 [2] e9 81 [2] fd 9a [2] f2 80 [2] ec 9d [2] ee 9c [2] f5 9a [2] e9 9d [2] f5 b2 }

  condition:
    any of them
}