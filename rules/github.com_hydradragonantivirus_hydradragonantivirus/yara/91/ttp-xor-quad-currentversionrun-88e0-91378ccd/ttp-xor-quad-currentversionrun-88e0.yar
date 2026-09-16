rule TTP_XOR_QUAD_CurrentVersionRun_88e0 {
  strings:
    $key_88e0 = { db 8f [2] ff 81 [2] d4 ad [2] fa 8f [2] ee 94 [2] e1 8e [2] ff 93 [2] fd 92 [2] e6 94 [2] fa 93 [2] e6 bc }

  condition:
    any of them
}