rule TTP_XOR_QUAD_CurrentVersionRun_8821 {
  strings:
    $key_8821 = { db 4e [2] ff 40 [2] d4 6c [2] fa 4e [2] ee 55 [2] e1 4f [2] ff 52 [2] fd 53 [2] e6 55 [2] fa 52 [2] e6 7d }

  condition:
    any of them
}