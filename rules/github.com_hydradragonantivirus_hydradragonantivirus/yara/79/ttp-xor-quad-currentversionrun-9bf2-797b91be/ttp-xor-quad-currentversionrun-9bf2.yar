rule TTP_XOR_QUAD_CurrentVersionRun_9bf2 {
  strings:
    $key_9bf2 = { c8 9d [2] ec 93 [2] c7 bf [2] e9 9d [2] fd 86 [2] f2 9c [2] ec 81 [2] ee 80 [2] f5 86 [2] e9 81 [2] f5 ae }

  condition:
    any of them
}