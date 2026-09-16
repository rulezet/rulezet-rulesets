rule TTP_XOR_QUAD_CurrentVersionRun_260f {
  strings:
    $key_260f = { 75 60 [2] 51 6e [2] 7a 42 [2] 54 60 [2] 40 7b [2] 4f 61 [2] 51 7c [2] 53 7d [2] 48 7b [2] 54 7c [2] 48 53 }

  condition:
    any of them
}