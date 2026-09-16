rule TTP_XOR_QUAD_CurrentVersionRun_87fe {
  strings:
    $key_87fe = { d4 91 [2] f0 9f [2] db b3 [2] f5 91 [2] e1 8a [2] ee 90 [2] f0 8d [2] f2 8c [2] e9 8a [2] f5 8d [2] e9 a2 }

  condition:
    any of them
}