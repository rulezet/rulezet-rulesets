rule TTP_XOR_QUAD_CurrentVersionRun_b22f {
  strings:
    $key_b22f = { e1 40 [2] c5 4e [2] ee 62 [2] c0 40 [2] d4 5b [2] db 41 [2] c5 5c [2] c7 5d [2] dc 5b [2] c0 5c [2] dc 73 }

  condition:
    any of them
}