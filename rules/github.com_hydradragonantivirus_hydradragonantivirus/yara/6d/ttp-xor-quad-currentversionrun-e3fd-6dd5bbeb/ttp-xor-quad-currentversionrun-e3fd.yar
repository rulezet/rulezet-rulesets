rule TTP_XOR_QUAD_CurrentVersionRun_e3fd {
  strings:
    $key_e3fd = { b0 92 [2] 94 9c [2] bf b0 [2] 91 92 [2] 85 89 [2] 8a 93 [2] 94 8e [2] 96 8f [2] 8d 89 [2] 91 8e [2] 8d a1 }

  condition:
    any of them
}