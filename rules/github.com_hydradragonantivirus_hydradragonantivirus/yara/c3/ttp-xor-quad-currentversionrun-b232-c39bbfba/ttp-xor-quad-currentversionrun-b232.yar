rule TTP_XOR_QUAD_CurrentVersionRun_b232 {
  strings:
    $key_b232 = { e1 5d [2] c5 53 [2] ee 7f [2] c0 5d [2] d4 46 [2] db 5c [2] c5 41 [2] c7 40 [2] dc 46 [2] c0 41 [2] dc 6e }

  condition:
    any of them
}