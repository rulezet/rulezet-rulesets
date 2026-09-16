rule TTP_XOR_QUAD_CurrentVersionRun_96ff {
  strings:
    $key_96ff = { c5 90 [2] e1 9e [2] ca b2 [2] e4 90 [2] f0 8b [2] ff 91 [2] e1 8c [2] e3 8d [2] f8 8b [2] e4 8c [2] f8 a3 }

  condition:
    any of them
}