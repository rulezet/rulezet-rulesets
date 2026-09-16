rule TTP_XOR_QUAD_CurrentVersionRun_8721 {
  strings:
    $key_8721 = { d4 4e [2] f0 40 [2] db 6c [2] f5 4e [2] e1 55 [2] ee 4f [2] f0 52 [2] f2 53 [2] e9 55 [2] f5 52 [2] e9 7d }

  condition:
    any of them
}