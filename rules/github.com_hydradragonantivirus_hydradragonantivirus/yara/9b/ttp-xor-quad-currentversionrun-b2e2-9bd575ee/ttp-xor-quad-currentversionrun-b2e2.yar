rule TTP_XOR_QUAD_CurrentVersionRun_b2e2 {
  strings:
    $key_b2e2 = { e1 8d [2] c5 83 [2] ee af [2] c0 8d [2] d4 96 [2] db 8c [2] c5 91 [2] c7 90 [2] dc 96 [2] c0 91 [2] dc be }

  condition:
    any of them
}