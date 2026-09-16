rule TTP_XOR_QUAD_CurrentVersionRun_783f {
  strings:
    $key_783f = { 2b 50 [2] 0f 5e [2] 24 72 [2] 0a 50 [2] 1e 4b [2] 11 51 [2] 0f 4c [2] 0d 4d [2] 16 4b [2] 0a 4c [2] 16 63 }

  condition:
    any of them
}