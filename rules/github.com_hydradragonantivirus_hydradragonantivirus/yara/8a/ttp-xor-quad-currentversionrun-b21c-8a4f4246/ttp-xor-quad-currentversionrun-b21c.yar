rule TTP_XOR_QUAD_CurrentVersionRun_b21c {
  strings:
    $key_b21c = { e1 73 [2] c5 7d [2] ee 51 [2] c0 73 [2] d4 68 [2] db 72 [2] c5 6f [2] c7 6e [2] dc 68 [2] c0 6f [2] dc 40 }

  condition:
    any of them
}