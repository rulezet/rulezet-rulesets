rule TTP_XOR_QUAD_CurrentVersionRun_b20e {
  strings:
    $key_b20e = { e1 61 [2] c5 6f [2] ee 43 [2] c0 61 [2] d4 7a [2] db 60 [2] c5 7d [2] c7 7c [2] dc 7a [2] c0 7d [2] dc 52 }

  condition:
    any of them
}