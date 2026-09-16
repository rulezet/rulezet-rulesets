rule TTP_XOR_QUAD_CurrentVersionRun_690f {
  strings:
    $key_690f = { 3a 60 [2] 1e 6e [2] 35 42 [2] 1b 60 [2] 0f 7b [2] 00 61 [2] 1e 7c [2] 1c 7d [2] 07 7b [2] 1b 7c [2] 07 53 }

  condition:
    any of them
}