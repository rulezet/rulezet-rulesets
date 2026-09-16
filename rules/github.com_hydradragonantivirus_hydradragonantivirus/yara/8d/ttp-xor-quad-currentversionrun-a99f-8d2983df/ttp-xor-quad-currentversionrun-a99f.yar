rule TTP_XOR_QUAD_CurrentVersionRun_a99f {
  strings:
    $key_a99f = { fa f0 [2] de fe [2] f5 d2 [2] db f0 [2] cf eb [2] c0 f1 [2] de ec [2] dc ed [2] c7 eb [2] db ec [2] c7 c3 }

  condition:
    any of them
}