rule TTP_XOR_QUAD_CurrentVersionRun_b26f {
  strings:
    $key_b26f = { e1 00 [2] c5 0e [2] ee 22 [2] c0 00 [2] d4 1b [2] db 01 [2] c5 1c [2] c7 1d [2] dc 1b [2] c0 1c [2] dc 33 }

  condition:
    any of them
}