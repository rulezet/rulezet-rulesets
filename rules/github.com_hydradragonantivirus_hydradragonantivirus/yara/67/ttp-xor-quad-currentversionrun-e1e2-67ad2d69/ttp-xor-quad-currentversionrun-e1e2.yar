rule TTP_XOR_QUAD_CurrentVersionRun_e1e2 {
  strings:
    $key_e1e2 = { b2 8d [2] 96 83 [2] bd af [2] 93 8d [2] 87 96 [2] 88 8c [2] 96 91 [2] 94 90 [2] 8f 96 [2] 93 91 [2] 8f be }

  condition:
    any of them
}