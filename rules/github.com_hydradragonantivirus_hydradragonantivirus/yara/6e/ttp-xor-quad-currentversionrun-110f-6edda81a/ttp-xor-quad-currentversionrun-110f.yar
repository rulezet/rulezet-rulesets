rule TTP_XOR_QUAD_CurrentVersionRun_110f {
  strings:
    $key_110f = { 42 60 [2] 66 6e [2] 4d 42 [2] 63 60 [2] 77 7b [2] 78 61 [2] 66 7c [2] 64 7d [2] 7f 7b [2] 63 7c [2] 7f 53 }

  condition:
    any of them
}