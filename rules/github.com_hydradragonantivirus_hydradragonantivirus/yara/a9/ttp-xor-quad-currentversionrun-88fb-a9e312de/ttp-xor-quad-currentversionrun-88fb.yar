rule TTP_XOR_QUAD_CurrentVersionRun_88fb {
  strings:
    $key_88fb = { db 94 [2] ff 9a [2] d4 b6 [2] fa 94 [2] ee 8f [2] e1 95 [2] ff 88 [2] fd 89 [2] e6 8f [2] fa 88 [2] e6 a7 }

  condition:
    any of them
}