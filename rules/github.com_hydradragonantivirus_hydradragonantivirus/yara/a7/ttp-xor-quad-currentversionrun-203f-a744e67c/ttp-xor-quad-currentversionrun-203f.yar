rule TTP_XOR_QUAD_CurrentVersionRun_203f {
  strings:
    $key_203f = { 73 50 [2] 57 5e [2] 7c 72 [2] 52 50 [2] 46 4b [2] 49 51 [2] 57 4c [2] 55 4d [2] 4e 4b [2] 52 4c [2] 4e 63 }

  condition:
    any of them
}