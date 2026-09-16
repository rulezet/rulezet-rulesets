rule TTP_XOR_QUAD_CurrentVersionRun_340f {
  strings:
    $key_340f = { 67 60 [2] 43 6e [2] 68 42 [2] 46 60 [2] 52 7b [2] 5d 61 [2] 43 7c [2] 41 7d [2] 5a 7b [2] 46 7c [2] 5a 53 }

  condition:
    any of them
}