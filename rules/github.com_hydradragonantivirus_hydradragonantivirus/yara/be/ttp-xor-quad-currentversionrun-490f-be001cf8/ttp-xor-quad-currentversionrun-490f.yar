rule TTP_XOR_QUAD_CurrentVersionRun_490f {
  strings:
    $key_490f = { 1a 60 [2] 3e 6e [2] 15 42 [2] 3b 60 [2] 2f 7b [2] 20 61 [2] 3e 7c [2] 3c 7d [2] 27 7b [2] 3b 7c [2] 27 53 }

  condition:
    any of them
}