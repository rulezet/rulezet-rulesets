rule TTP_XOR_QUAD_CurrentVersionRun_88e3 {
  strings:
    $key_88e3 = { db 8c [2] ff 82 [2] d4 ae [2] fa 8c [2] ee 97 [2] e1 8d [2] ff 90 [2] fd 91 [2] e6 97 [2] fa 90 [2] e6 bf }

  condition:
    any of them
}