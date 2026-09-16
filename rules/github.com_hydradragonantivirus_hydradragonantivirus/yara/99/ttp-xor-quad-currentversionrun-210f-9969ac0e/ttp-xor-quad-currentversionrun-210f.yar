rule TTP_XOR_QUAD_CurrentVersionRun_210f {
  strings:
    $key_210f = { 72 60 [2] 56 6e [2] 7d 42 [2] 53 60 [2] 47 7b [2] 48 61 [2] 56 7c [2] 54 7d [2] 4f 7b [2] 53 7c [2] 4f 53 }

  condition:
    any of them
}