rule TTP_XOR_QUAD_CurrentVersionRun_b21f {
  strings:
    $key_b21f = { e1 70 [2] c5 7e [2] ee 52 [2] c0 70 [2] d4 6b [2] db 71 [2] c5 6c [2] c7 6d [2] dc 6b [2] c0 6c [2] dc 43 }

  condition:
    any of them
}