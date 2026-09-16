rule TTP_XOR_QUAD_CurrentVersionRun_88f1 {
  strings:
    $key_88f1 = { db 9e [2] ff 90 [2] d4 bc [2] fa 9e [2] ee 85 [2] e1 9f [2] ff 82 [2] fd 83 [2] e6 85 [2] fa 82 [2] e6 ad }

  condition:
    any of them
}