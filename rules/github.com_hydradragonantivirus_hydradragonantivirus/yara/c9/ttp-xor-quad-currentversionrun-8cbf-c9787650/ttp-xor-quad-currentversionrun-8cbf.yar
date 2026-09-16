rule TTP_XOR_QUAD_CurrentVersionRun_8cbf {
  strings:
    $key_8cbf = { df d0 [2] fb de [2] d0 f2 [2] fe d0 [2] ea cb [2] e5 d1 [2] fb cc [2] f9 cd [2] e2 cb [2] fe cc [2] e2 e3 }

  condition:
    any of them
}