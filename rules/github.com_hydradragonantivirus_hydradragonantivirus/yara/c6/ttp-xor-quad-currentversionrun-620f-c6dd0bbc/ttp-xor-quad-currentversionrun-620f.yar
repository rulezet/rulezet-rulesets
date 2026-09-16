rule TTP_XOR_QUAD_CurrentVersionRun_620f {
  strings:
    $key_620f = { 31 60 [2] 15 6e [2] 3e 42 [2] 10 60 [2] 04 7b [2] 0b 61 [2] 15 7c [2] 17 7d [2] 0c 7b [2] 10 7c [2] 0c 53 }

  condition:
    any of them
}