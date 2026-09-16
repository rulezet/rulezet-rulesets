rule TTP_XOR_QUAD_CurrentVersionRun_96fd {
  strings:
    $key_96fd = { c5 92 [2] e1 9c [2] ca b0 [2] e4 92 [2] f0 89 [2] ff 93 [2] e1 8e [2] e3 8f [2] f8 89 [2] e4 8e [2] f8 a1 }

  condition:
    any of them
}