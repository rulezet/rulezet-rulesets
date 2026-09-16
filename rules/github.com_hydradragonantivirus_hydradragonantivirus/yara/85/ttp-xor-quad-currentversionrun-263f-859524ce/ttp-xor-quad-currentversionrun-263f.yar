rule TTP_XOR_QUAD_CurrentVersionRun_263f {
  strings:
    $key_263f = { 75 50 [2] 51 5e [2] 7a 72 [2] 54 50 [2] 40 4b [2] 4f 51 [2] 51 4c [2] 53 4d [2] 48 4b [2] 54 4c [2] 48 63 }

  condition:
    any of them
}