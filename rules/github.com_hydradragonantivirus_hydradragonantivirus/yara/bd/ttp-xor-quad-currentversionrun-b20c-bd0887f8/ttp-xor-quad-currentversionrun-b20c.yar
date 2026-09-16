rule TTP_XOR_QUAD_CurrentVersionRun_b20c {
  strings:
    $key_b20c = { e1 63 [2] c5 6d [2] ee 41 [2] c0 63 [2] d4 78 [2] db 62 [2] c5 7f [2] c7 7e [2] dc 78 [2] c0 7f [2] dc 50 }

  condition:
    any of them
}