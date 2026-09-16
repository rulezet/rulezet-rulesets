rule TTP_XOR_QUAD_CurrentVersionRun_88eb {
  strings:
    $key_88eb = { db 84 [2] ff 8a [2] d4 a6 [2] fa 84 [2] ee 9f [2] e1 85 [2] ff 98 [2] fd 99 [2] e6 9f [2] fa 98 [2] e6 b7 }

  condition:
    any of them
}