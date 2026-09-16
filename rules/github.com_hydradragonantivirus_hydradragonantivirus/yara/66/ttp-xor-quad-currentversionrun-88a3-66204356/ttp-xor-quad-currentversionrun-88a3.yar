rule TTP_XOR_QUAD_CurrentVersionRun_88a3 {
  strings:
    $key_88a3 = { db cc [2] ff c2 [2] d4 ee [2] fa cc [2] ee d7 [2] e1 cd [2] ff d0 [2] fd d1 [2] e6 d7 [2] fa d0 [2] e6 ff }

  condition:
    any of them
}