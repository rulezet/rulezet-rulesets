rule TTP_XOR_QUAD_CurrentVersionRun_9bc8 {
  strings:
    $key_9bc8 = { c8 a7 [2] ec a9 [2] c7 85 [2] e9 a7 [2] fd bc [2] f2 a6 [2] ec bb [2] ee ba [2] f5 bc [2] e9 bb [2] f5 94 }

  condition:
    any of them
}