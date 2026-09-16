rule TTP_XOR_QUAD_CurrentVersionRun_8dbe {
  strings:
    $key_8dbe = { de d1 [2] fa df [2] d1 f3 [2] ff d1 [2] eb ca [2] e4 d0 [2] fa cd [2] f8 cc [2] e3 ca [2] ff cd [2] e3 e2 }

  condition:
    any of them
}