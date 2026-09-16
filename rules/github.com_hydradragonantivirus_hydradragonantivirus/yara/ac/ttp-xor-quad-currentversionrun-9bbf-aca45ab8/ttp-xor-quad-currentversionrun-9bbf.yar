rule TTP_XOR_QUAD_CurrentVersionRun_9bbf {
  strings:
    $key_9bbf = { c8 d0 [2] ec de [2] c7 f2 [2] e9 d0 [2] fd cb [2] f2 d1 [2] ec cc [2] ee cd [2] f5 cb [2] e9 cc [2] f5 e3 }

  condition:
    any of them
}