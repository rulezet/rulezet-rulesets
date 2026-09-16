rule TTP_XOR_QUAD_CurrentVersionRun_b23f {
  strings:
    $key_b23f = { e1 50 [2] c5 5e [2] ee 72 [2] c0 50 [2] d4 4b [2] db 51 [2] c5 4c [2] c7 4d [2] dc 4b [2] c0 4c [2] dc 63 }

  condition:
    any of them
}