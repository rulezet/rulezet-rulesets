rule TTP_XOR_QUAD_CurrentVersionRun_11ff {
  strings:
    $key_11ff = { 42 90 [2] 66 9e [2] 4d b2 [2] 63 90 [2] 77 8b [2] 78 91 [2] 66 8c [2] 64 8d [2] 7f 8b [2] 63 8c [2] 7f a3 }

  condition:
    any of them
}