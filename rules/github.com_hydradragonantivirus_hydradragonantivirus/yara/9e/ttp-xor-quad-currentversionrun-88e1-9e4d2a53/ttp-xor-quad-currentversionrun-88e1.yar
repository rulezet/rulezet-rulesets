rule TTP_XOR_QUAD_CurrentVersionRun_88e1 {
  strings:
    $key_88e1 = { db 8e [2] ff 80 [2] d4 ac [2] fa 8e [2] ee 95 [2] e1 8f [2] ff 92 [2] fd 93 [2] e6 95 [2] fa 92 [2] e6 bd }

  condition:
    any of them
}