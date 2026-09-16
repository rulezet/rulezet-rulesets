rule TTP_XOR_QUAD_CurrentVersionRun_fcef {
  strings:
    $key_fcef = { af 80 [2] 8b 8e [2] a0 a2 [2] 8e 80 [2] 9a 9b [2] 95 81 [2] 8b 9c [2] 89 9d [2] 92 9b [2] 8e 9c [2] 92 b3 }

  condition:
    any of them
}