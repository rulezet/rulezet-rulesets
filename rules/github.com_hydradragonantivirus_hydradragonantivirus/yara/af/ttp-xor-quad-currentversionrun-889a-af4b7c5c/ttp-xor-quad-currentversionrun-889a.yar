rule TTP_XOR_QUAD_CurrentVersionRun_889a {
  strings:
    $key_889a = { db f5 [2] ff fb [2] d4 d7 [2] fa f5 [2] ee ee [2] e1 f4 [2] ff e9 [2] fd e8 [2] e6 ee [2] fa e9 [2] e6 c6 }

  condition:
    any of them
}