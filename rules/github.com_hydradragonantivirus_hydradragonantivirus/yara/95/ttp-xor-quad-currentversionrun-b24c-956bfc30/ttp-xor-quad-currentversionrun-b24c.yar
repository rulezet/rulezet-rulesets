rule TTP_XOR_QUAD_CurrentVersionRun_b24c {
  strings:
    $key_b24c = { e1 23 [2] c5 2d [2] ee 01 [2] c0 23 [2] d4 38 [2] db 22 [2] c5 3f [2] c7 3e [2] dc 38 [2] c0 3f [2] dc 10 }

  condition:
    any of them
}