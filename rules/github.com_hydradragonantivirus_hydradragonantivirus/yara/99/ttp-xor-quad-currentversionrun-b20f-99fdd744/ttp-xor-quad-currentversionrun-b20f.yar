rule TTP_XOR_QUAD_CurrentVersionRun_b20f {
  strings:
    $key_b20f = { e1 60 [2] c5 6e [2] ee 42 [2] c0 60 [2] d4 7b [2] db 61 [2] c5 7c [2] c7 7d [2] dc 7b [2] c0 7c [2] dc 53 }

  condition:
    any of them
}