rule TTP_XOR_QUAD_CurrentVersionRun_88be {
  strings:
    $key_88be = { db d1 [2] ff df [2] d4 f3 [2] fa d1 [2] ee ca [2] e1 d0 [2] ff cd [2] fd cc [2] e6 ca [2] fa cd [2] e6 e2 }

  condition:
    any of them
}