rule TTP_XOR_QUAD_CurrentVersionRun_103f {
  strings:
    $key_103f = { 43 50 [2] 67 5e [2] 4c 72 [2] 62 50 [2] 76 4b [2] 79 51 [2] 67 4c [2] 65 4d [2] 7e 4b [2] 62 4c [2] 7e 63 }

  condition:
    any of them
}