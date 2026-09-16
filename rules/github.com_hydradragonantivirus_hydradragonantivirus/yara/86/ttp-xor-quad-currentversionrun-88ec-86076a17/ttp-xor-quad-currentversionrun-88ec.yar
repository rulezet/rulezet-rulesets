rule TTP_XOR_QUAD_CurrentVersionRun_88ec {
  strings:
    $key_88ec = { db 83 [2] ff 8d [2] d4 a1 [2] fa 83 [2] ee 98 [2] e1 82 [2] ff 9f [2] fd 9e [2] e6 98 [2] fa 9f [2] e6 b0 }

  condition:
    any of them
}