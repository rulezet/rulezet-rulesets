rule TTP_XOR_QUAD_CurrentVersionRun_9bf9 {
  strings:
    $key_9bf9 = { c8 96 [2] ec 98 [2] c7 b4 [2] e9 96 [2] fd 8d [2] f2 97 [2] ec 8a [2] ee 8b [2] f5 8d [2] e9 8a [2] f5 a5 }

  condition:
    any of them
}