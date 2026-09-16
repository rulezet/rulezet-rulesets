rule TTP_XOR_QUAD_CurrentVersionRun_9be5 {
  strings:
    $key_9be5 = { c8 8a [2] ec 84 [2] c7 a8 [2] e9 8a [2] fd 91 [2] f2 8b [2] ec 96 [2] ee 97 [2] f5 91 [2] e9 96 [2] f5 b9 }

  condition:
    any of them
}