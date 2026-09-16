rule TTP_XOR_QUAD_CurrentVersionRun_8866 {
  strings:
    $key_8866 = { db 09 [2] ff 07 [2] d4 2b [2] fa 09 [2] ee 12 [2] e1 08 [2] ff 15 [2] fd 14 [2] e6 12 [2] fa 15 [2] e6 3a }

  condition:
    any of them
}