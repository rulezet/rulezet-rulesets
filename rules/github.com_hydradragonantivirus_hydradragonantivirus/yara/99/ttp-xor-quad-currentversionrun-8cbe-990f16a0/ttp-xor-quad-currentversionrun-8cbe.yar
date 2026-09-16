rule TTP_XOR_QUAD_CurrentVersionRun_8cbe {
  strings:
    $key_8cbe = { df d1 [2] fb df [2] d0 f3 [2] fe d1 [2] ea ca [2] e5 d0 [2] fb cd [2] f9 cc [2] e2 ca [2] fe cd [2] e2 e2 }

  condition:
    any of them
}