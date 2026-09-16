rule TTP_XOR_QUAD_CurrentVersionRun_9be9 {
  strings:
    $key_9be9 = { c8 86 [2] ec 88 [2] c7 a4 [2] e9 86 [2] fd 9d [2] f2 87 [2] ec 9a [2] ee 9b [2] f5 9d [2] e9 9a [2] f5 b5 }

  condition:
    any of them
}